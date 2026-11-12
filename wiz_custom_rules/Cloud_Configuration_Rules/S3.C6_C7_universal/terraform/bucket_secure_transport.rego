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

# A statement written with NotResource, NotAction or NotPrincipal is never
# counted as the covering deny.
not_keys := {
    "NotResource", "NotResources", "NotAction", "NotActions", "NotPrincipal", "NotPrincipals",
    "not_resources", "not_actions", "not_principals",
}

is_set_value(v) {
    v != null
    v != []
    v != {}
    v != ""
}

json_uses_not(stmt) { is_set_value(stmt[not_keys[_]]) }

hcl_uses_not(stmt) { is_set_value(stmt[not_keys[_]]) }

# Resources named by every Deny that enforces the given protection
# ("transport" or "tls") for all principals and all S3 actions.
deny_resources(document, pol, kind) := json_rs | hcl_rs {
    json_rs := {r |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        not json_uses_not(stmt)
        json_covers_all_s3(stmt)
        json_everyone(stmt)
        json_qualifies(stmt, kind)
        r := stmt_resources(stmt)[_]
    }
    hcl_rs := {r |
        is_string(pol.policy)
        ds := document.data.aws_iam_policy_document[policy_data_source_name(pol.policy)]
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        not hcl_uses_not(stmt)
        hcl_covers_all_s3(stmt)
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        hcl_qualifies(conds[0], kind)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Resource scope ---
# The deny must reach the bucket itself and every object in it.
scope_targets := {"bucket", "objects"}

partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

# A pattern reaches the bucket when it matches the bucket ARN, and the objects
# only when it leaves no key out.
pattern_reaches(pattern, arn, "bucket") {
    tocm_iam_pattern_matches(pattern, arn)
}

pattern_reaches(pattern, arn, "objects") {
    tocm_s3_pattern_covers_objects(pattern, arn)
}

resource_reaches(r, bucket, name, target) {
    r == "*"
}

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it, with "x" standing for the bucket ARN.
resource_reaches(r, bucket, name, target) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    pattern_reaches(concat("", ["x", m[3]]), "x", target)
}

resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    pattern_reaches(r, sprintf("arn:%s:s3:::%s", [partitions[_], n]), target)
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
# Qualifying denies may split the bucket and its objects across statements.

bucket_enforces(document, bucket, name, kind) {
    reached := {target |
        pol := document.resource.aws_s3_bucket_policy[pName]
        terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
        r := deny_resources(document, pol, kind)[_]
        scope_targets[target]
        resource_reaches(r, bucket, name, target)
    }
    count(reached) == count(scope_targets)
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
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny statement for all principals and all S3 actions on the bucket and every object in it when aws:SecureTransport is false, with no other condition", [name]),
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
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny statement for all principals and all S3 actions on the bucket and every object in it when s3:TlsVersion is below 1.2, with no other condition", [name]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy statement denying TLS versions below 1.2 at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# The data block a policy names: data.aws_iam_policy_document.<name>.json,
# written with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}

# --- Matching helpers ---
# --- toc-match begin: iampattern v1 ---
# An IAM policy pattern as a regular expression: "*" is any run of characters
# ("/", ":" and a line break included), "?" is any one character, and every
# other character stands for itself.
tocm_iam_pattern_regex(p) := concat("", ["(?s)^", body, "$"]) {
    is_string(p)
    body := strings.replace_n({
        "\\": "\\\\", ".": "\\.", "+": "\\+", "(": "\\(", ")": "\\)", "|": "\\|",
        "[": "\\[", "]": "\\]", "{": "\\{", "}": "\\}", "^": "\\^", "$": "\\$",
        "*": ".*", "?": "."
    }, p)
}

# The pattern matches this one value.
tocm_iam_pattern_matches(p, value) {
    is_string(value)
    regex.match(tocm_iam_pattern_regex(p), value)
}

# The pattern matches every value that starts with base. It must end in "*",
# and what stands before that "*" must match base or the start of base. So
# "arn:aws:s3:::logs/*" and "arn:aws:s3:::lo*" cover everything under
# "arn:aws:s3:::logs/", and "arn:aws:s3:::logs/a*" does not.
tocm_iam_pattern_covers_prefix(p, base) {
    is_string(p)
    is_string(base)
    endswith(p, "*")
    head := tocm_iam_pattern_regex(substring(p, 0, count(p) - 1))
    n := numbers.range(0, count(base))[_]
    regex.match(head, substring(base, 0, n))
}

# The pattern matches every value made of base and at least one more
# character. Use it where that part is never empty, such as an object key
# after "<bucket ARN>/": "arn:aws:s3:::logs/?*" then covers every object of
# the bucket. What stands before the final "*" must match base or the start of
# base, or match base and any one character; a match for two different
# characters can only come from a wildcard.
tocm_iam_pattern_covers_nonempty(p, base) {
    tocm_iam_pattern_covers_prefix(p, base)
}

tocm_iam_pattern_covers_nonempty(p, base) {
    is_string(p)
    is_string(base)
    endswith(p, "*")
    head := tocm_iam_pattern_regex(substring(p, 0, count(p) - 1))
    regex.match(head, concat("", [base, "a"]))
    regex.match(head, concat("", [base, "b"]))
}

# Every object of one bucket, given the bucket ARN. An object key is never
# empty.
tocm_s3_pattern_covers_objects(p, bucket_arn) {
    tocm_iam_pattern_covers_nonempty(p, concat("", [bucket_arn, "/"]))
}

# Every bucket of a partition, and every object in them. A bucket name is
# never empty.
tocm_s3_pattern_covers_all(p, partition) {
    tocm_iam_pattern_covers_nonempty(p, concat("", ["arn:", partition, ":s3:::"]))
}

# Every object of every bucket of a partition; "arn:<partition>:s3:::*/*" is
# the usual way to write it, and "?*" may stand for either "*".
tocm_s3_pattern_covers_all_objects(p, partition) {
    tocm_s3_pattern_covers_all(p, partition)
}

tocm_s3_pattern_covers_all_objects(p, partition) {
    names := {"*", "?*"}
    p == concat("", ["arn:", partition, ":s3:::", names[_], "/", names[_]])
}
# --- toc-match end: iampattern v1 ---
