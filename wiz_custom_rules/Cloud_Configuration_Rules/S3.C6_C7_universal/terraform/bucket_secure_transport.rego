package wiz

import data.generic.terraform as terraLib

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

json_covers_all_s3(stmt) { stmt_actions(stmt)[_] == "s3:*" }
json_covers_all_s3(stmt) { stmt_actions(stmt)[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

json_everyone(stmt) { stmt.Principal == "*" }
json_everyone(stmt) { wildcard(stmt.Principal.AWS) }
json_everyone(stmt) { wildcard(stmt.Principals["*"]) }
json_everyone(stmt) { wildcard(stmt.Principals.AWS) }

value_false(v) { v == "false" }
value_false(v) { v == false }
value_false(v) { v[_] == "false" }

tls_floor_ok(v) { to_number(v) >= 1.2 }
tls_floor_ok(v) { to_number(v[_]) >= 1.2 }

# The transport test must be the only condition; any extra key narrows the deny.
json_sole_condition(stmt, operator) {
    count(stmt.Condition) == 1
    count(stmt.Condition[operator]) == 1
}

json_qualifies(stmt, "transport") {
    json_sole_condition(stmt, "Bool")
    value_false(stmt.Condition.Bool["aws:SecureTransport"])
}

json_qualifies(stmt, "tls") {
    json_sole_condition(stmt, "NumericLessThan")
    tls_floor_ok(stmt.Condition.NumericLessThan["s3:TlsVersion"])
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

# Raw data-block walk (unresolved "${data.aws_iam_policy_document...}" refs).
hcl_covers_all_s3(stmt) { terraLib.getArray(stmt.actions)[_] == "s3:*" }
hcl_covers_all_s3(stmt) { terraLib.getArray(stmt.actions)[_] == "*" }

hcl_everyone(stmt) {
    p := terraLib.getArray(stmt.principals)[_]
    {"*", "AWS"}[p.type]
    wildcard(p.identifiers)
}

hcl_qualifies(c, "transport") {
    c.test == "Bool"
    c.variable == "aws:SecureTransport"
    value_false(c.values)
}

hcl_qualifies(c, "tls") {
    c.test == "NumericLessThan"
    c.variable == "s3:TlsVersion"
    tls_floor_ok(c.values)
}

# Resources named by every Deny that enforces the given protection
# ("transport" or "tls") for all principals and all S3 actions.
deny_resources(document, pol, kind) := json_rs | hcl_rs {
    json_rs := {r |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        json_covers_all_s3(stmt)
        json_everyone(stmt)
        json_qualifies(stmt, kind)
        r := stmt_resources(stmt)[_]
    }
    hcl_rs := {r |
        is_string(pol.policy)
        ds := document.data.aws_iam_policy_document[dsName]
        contains(pol.policy, dsName)
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        hcl_covers_all_s3(stmt)
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        hcl_qualifies(conds[0], kind)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Resource scope ---
# The deny must reach the bucket itself and every object in it; the sample
# object key stands in for any key.
scope_suffixes := {"bucket": "", "objects": "/sample-object"}

partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

resource_reaches(r, bucket, name, target) {
    r == "*"
}

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it.
resource_reaches(r, bucket, name, target) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    glob.match(concat("", ["x", m[3]]), [], concat("", ["x", scope_suffixes[target]]))
}

resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    glob.match(r, [], sprintf("arn:%s:s3:::%s%s", [partitions[_], n, scope_suffixes[target]]))
}

# Values that cannot be resolved statically (a generated bucket name, variables,
# locals, module outputs) are given the benefit of the doubt.
resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    not literal_bucket_name(bucket)
}

resource_reaches(r, bucket, name, target) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

resource_reaches(r, bucket, name, target) {
    regex.match(`^(var|local|module|data)\.`, r)
}

# --- Logic ---
# Both protections are required; each missing protection is its own finding.
# Qualifying denies may split the bucket and object ARNs across statements.

bucket_enforces(document, bucket, name, kind) {
    reached := {target |
        pol := document.resource.aws_s3_bucket_policy[pName]
        terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
        r := deny_resources(document, pol, kind)[_]
        scope_suffixes[target]
        resource_reaches(r, bucket, name, target)
    }
    count(reached) == count(scope_suffixes)
}

WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not bucket_enforces(document, bucket, name, "transport")

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny statement for all principals and all S3 actions on the bucket and its objects when aws:SecureTransport is false, with no other condition", [name]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy statement denying unencrypted requests at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not bucket_enforces(document, bucket, name, "tls")

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny statement for all principals and all S3 actions on the bucket and its objects when s3:TlsVersion is below 1.2, with no other condition", [name]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy statement denying TLS versions below 1.2 at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
