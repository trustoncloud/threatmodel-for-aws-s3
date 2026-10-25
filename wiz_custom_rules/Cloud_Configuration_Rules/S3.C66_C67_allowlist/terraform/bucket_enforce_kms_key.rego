package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_kms_key_ids := {
    "arn:aws:kms:us-east-1:123456789012:key/authorized-key",
}

# --- Policy helpers ---
# Policies reach the matcher in three shapes: a JSON string with real IAM keys
# (jsonencode or heredoc), a JSON string with resolved data-source keys
# (Actions/Resources/Principals, condition values as arrays), or an unresolved
# reference to an aws_iam_policy_document data block (walked directly,
# lowercase names).

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

stmt_actions(stmt) := terraLib.getArray(stmt.Action)
stmt_actions(stmt) := terraLib.getArray(stmt.Actions)

stmt_resources(stmt) := terraLib.getArray(stmt.Resource)
stmt_resources(stmt) := terraLib.getArray(stmt.Resources)

put_object_actions := {"s3:PutObject", "s3:*", "*"}

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

json_everyone(stmt) { stmt.Principal == "*" }
json_everyone(stmt) { wildcard(stmt.Principal.AWS) }
json_everyone(stmt) { wildcard(stmt.Principals["*"]) }
json_everyone(stmt) { wildcard(stmt.Principals.AWS) }

hcl_everyone(stmt) {
    p := terraLib.getArray(stmt.principals)[_]
    {"*", "AWS"}[p.type]
    wildcard(p.identifiers)
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

only_authorized(values) {
    vals := {v | v := terraLib.getArray(values)[_]}
    count(vals) > 0
    count(vals - authorized_kms_key_ids) == 0
}

# Resources of every Deny on PutObject for everyone whose only condition is a
# StringNotEquals on the KMS key header, listing only authorized keys.
key_deny_resources(document, pol) := json_rs | hcl_rs {
    json_rs := {r |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        put_object_actions[stmt_actions(stmt)[_]]
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        restriction_operators[lower(operator)]
        count(conditions) == 1
        val := conditions[key]
        lower(key) == "s3:x-amz-server-side-encryption-aws-kms-key-id"
        only_authorized(val)
        r := stmt_resources(stmt)[_]
    }
    hcl_rs := {r |
        is_string(pol.policy)
        ds := document.data.aws_iam_policy_document[dsName]
        contains(pol.policy, dsName)
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        put_object_actions[terraLib.getArray(stmt.actions)[_]]
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        c := conds[0]
        restriction_operators[lower(c.test)]
        lower(c.variable) == "s3:x-amz-server-side-encryption-aws-kms-key-id"
        only_authorized(c.values)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Resource scope ---
# The deny must reach every object in the bucket; the sample object key stands
# in for any key.
object_suffix := "/sample-object"

partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

reaches_objects(r, bucket, name) {
    r == "*"
}

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it.
reaches_objects(r, bucket, name) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    glob.match(concat("", ["x", m[3]]), [], concat("", ["x", object_suffix]))
}

reaches_objects(r, bucket, name) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    glob.match(r, [], sprintf("arn:%s:s3:::%s%s", [partitions[_], n, object_suffix]))
}

# Values that cannot be resolved statically (a generated bucket name, variables,
# locals, module outputs) are given the benefit of the doubt.
reaches_objects(r, bucket, name) {
    not contains(r, "${")
    not literal_bucket_name(bucket)
}

reaches_objects(r, bucket, name) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

reaches_objects(r, bucket, name) {
    regex.match(`^(var|local|module|data)\.`, r)
}

bucket_enforces_key(document, bucket, name) {
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    reaches_objects(key_deny_resources(document, pol)[_], bucket, name)
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not bucket_enforces_key(document, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy denying s3:PutObject for all principals on every object when the KMS key is not in the authorized set, with no other condition: %v", [name, authorized_kms_key_ids]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy enforcing the authorized KMS key(s) at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
