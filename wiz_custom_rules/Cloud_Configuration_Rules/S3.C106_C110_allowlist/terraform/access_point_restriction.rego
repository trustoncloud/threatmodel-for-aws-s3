package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_access_points := {
    "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap",
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

json_covers_all_s3(stmt) { stmt_actions(stmt)[_] == "s3:*" }
json_covers_all_s3(stmt) { stmt_actions(stmt)[_] == "*" }

hcl_covers_all_s3(stmt) { terraLib.getArray(stmt.actions)[_] == "s3:*" }
hcl_covers_all_s3(stmt) { terraLib.getArray(stmt.actions)[_] == "*" }

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

# The data block a policy names: data.aws_iam_policy_document.<name>.json.
policy_data_source(pol) := m[1] {
    is_string(pol.policy)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json\s*\}?\s*$`, pol.policy, 1)[0]
}

# A Deny for everyone on all S3 actions whose only condition is a
# StringNotEquals on s3:DataAccessPointArn allows exactly the listed access
# points.
ap_restrictions(document, pol) := json_rs | hcl_rs {
    json_rs := {{"resources": stmt_resources(stmt), "aps": terraLib.getArray(val)} |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        json_covers_all_s3(stmt)
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        restriction_operators[lower(operator)]
        count(conditions) == 1
        val := conditions[key]
        lower(key) == "s3:dataaccesspointarn"
    }
    hcl_rs := {{"resources": terraLib.getArray(stmt.resources), "aps": terraLib.getArray(c.values)} |
        ds := document.data.aws_iam_policy_document[policy_data_source(pol)]
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        hcl_covers_all_s3(stmt)
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        c := conds[0]
        restriction_operators[lower(c.test)]
        lower(c.variable) == "s3:dataaccesspointarn"
    }
}

bucket_restrictions(document, bucket, name) := {r |
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    r := ap_restrictions(document, pol)[_]
}

# --- Resource scope ---
# The deny must reach every object in the bucket: one Resource pattern must
# leave no key out. Covering the bucket ARN as well is accepted but not
# required, since bucket settings calls cannot go through an access point.

partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

tf_covers_every_object(r, bucket, name) {
    r == "*"
}

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it ("/*" and "/?*" reach every object, "/s*" does not).
tf_covers_every_object(r, bucket, name) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    tocm_s3_pattern_covers_objects(concat("", ["x", m[3]]), "x")
}

tf_covers_every_object(r, bucket, name) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    tocm_s3_pattern_covers_objects(r, sprintf("arn:%s:s3:::%s", [partitions[_], n]))
}

# Values that cannot be resolved statically (a generated bucket name, variables,
# locals, module outputs) are given the benefit of the doubt.
tf_covers_every_object(r, bucket, name) {
    not contains(r, "${")
    not literal_bucket_name(bucket)
}

tf_covers_every_object(r, bucket, name) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

tf_covers_every_object(r, bucket, name) {
    regex.match(`^(var|local|module|data)\.`, r)
}

has_restriction(document, bucket, name) {
    r := bucket_restrictions(document, bucket, name)[_]
    tf_covers_every_object(r.resources[_], bucket, name)
}

allowed_aps(document, bucket, name) := {ap |
    ap := bucket_restrictions(document, bucket, name)[_].aps[_]
}

# --- Logic ---
# Fail 1: no access point restriction on the bucket at the required scope.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not has_restriction(document, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny for all principals and all S3 actions on every object whose only condition is StringNotEquals on s3:DataAccessPointArn, listing only authorized access points: %v", [name, authorized_access_points]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy restricting access to authorized access points at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Fail 2: a restriction exists but allows an access point outside the set.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    unauth := allowed_aps(document, bucket, name) - authorized_access_points
    count(unauth) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must only allow authorized access points: %v", [name, authorized_access_points]),
        "keyActualValue": sprintf("bucket '%s' policy allows unauthorized access point(s): %v", [name, unauth]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
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
