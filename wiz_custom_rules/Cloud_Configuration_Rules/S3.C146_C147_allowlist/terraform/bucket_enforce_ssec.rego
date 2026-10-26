package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Buckets that must enforce SSE-C on PutObject: a bucket name for the whole
# bucket, or "bucket/prefix/" for one path inside it. Keep in sync with the
# cloud matcher.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
}

# --- Policy helpers ---
# Policies reach the matcher in three shapes: a JSON string with real IAM keys
# (jsonencode or heredoc), a JSON string with resolved data-source keys
# (Actions/Resources/Principals, condition values as arrays), or an unresolved
# reference to an aws_iam_policy_document data block (walked directly,
# lowercase names).

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

value_is(v, target) { v == target }
value_is(v, target) { v[_] == target }

ssec_key := "s3:x-amz-server-side-encryption-customer-algorithm"

# The SSE-C test must be the only condition: a StringNotEquals AES256 or a
# Null true on the customer-algorithm header.
enforcing_test(operator, key, values) {
    {"stringnotequals", "stringnotequalsifexists"}[lower(operator)]
    lower(key) == ssec_key
    value_is(values, "AES256")
}

enforcing_test(operator, key, values) {
    lower(operator) == "null"
    lower(key) == ssec_key
    value_is(values, "true")
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

# Resources of every Deny on PutObject for everyone that enforces SSE-C.
ssec_deny_resources(document, pol) := json_rs | hcl_rs {
    json_rs := {r |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        put_object_actions[stmt_actions(stmt)[_]]
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        count(conditions) == 1
        val := conditions[key]
        enforcing_test(operator, key, val)
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
        enforcing_test(conds[0].test, conds[0].variable, conds[0].values)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Required paths ---
# The bucket name is the `bucket` argument, falling back to the local name.
bucket_name(bucket, name) := object.get(bucket, "bucket", name)

# Paths of a bucket that require SSE-C; "" stands for the whole bucket.
tf_required_prefixes(bname) := whole | paths {
    whole := {"" | buckets_requiring_ssec[bname]}
    paths := {prefix |
        entry := buckets_requiring_ssec[_]
        startswith(entry, concat("", [bname, "/"]))
        path := trim_suffix(trim_prefix(entry, concat("", [bname, "/"])), "/")
        path != ""
        prefix := concat("", [path, "/"])
    }
}

# --- Resource scope ---
# A sample object under the required path stands in for any key there.
partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

reaches_path(r, bucket, name, prefix) {
    r == "*"
}

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it.
reaches_path(r, bucket, name, prefix) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    glob.match(concat("", ["x", m[3]]), [], sprintf("x/%ssample-object", [prefix]))
}

reaches_path(r, bucket, name, prefix) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    glob.match(r, [], sprintf("arn:%s:s3:::%s/%ssample-object", [partitions[_], n, prefix]))
}

# Values that cannot be resolved statically (variables, locals, module
# outputs) are given the benefit of the doubt.
reaches_path(r, bucket, name, prefix) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

reaches_path(r, bucket, name, prefix) {
    regex.match(`^(var|local|module|data)\.`, r)
}

tf_enforced_prefixes(document, bucket, name, required) := {prefix |
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    r := ssec_deny_resources(document, pol)[_]
    prefix := required[_]
    reaches_path(r, bucket, name, prefix)
}

path_label(prefix) := "the whole bucket" { prefix == "" } else := prefix

# --- Logic ---
# Only buckets with a required path are checked.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    bname := bucket_name(bucket, name)
    required := tf_required_prefixes(bname)
    count(required) > 0
    missing := required - tf_enforced_prefixes(document, bucket, name, required)
    count(missing) > 0
    labels := concat(", ", sort([path_label(p) | p := missing[_]]))

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' requires SSE-C on %s and must have a bucket policy denying s3:PutObject there for all principals when the customer-algorithm header is missing or not AES256, with no other condition", [bname, labels]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy enforcing SSE-C on %s", [bname, labels]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
