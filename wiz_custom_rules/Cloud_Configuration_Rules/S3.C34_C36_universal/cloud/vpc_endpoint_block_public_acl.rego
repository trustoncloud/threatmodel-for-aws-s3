package wiz

# --- Logic ---
default result := "pass"

is_s3_endpoint {
    endswith(input.ServiceName, ".s3")
}

policy_doc := doc {
    is_string(input.PolicyDocument)
    doc := json.unmarshal(input.PolicyDocument)
} else := doc {
    is_object(input.PolicyDocument)
    doc := input.PolicyDocument
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

as_array(v) := v { is_array(v) } else := [v]

# s3:PutObjectVersionAcl applies when a request names a version. An upload
# with an ACL also needs s3:PutObjectAcl, so this deny covers uploads too.
acl_actions := {"s3:PutObjectAcl", "s3:PutObjectVersionAcl"}

covers_action(stmt, action) {
    tocm_iam_pattern_matches(lower(as_array(stmt.Action)[_]), lower(action))
}

applies_to_everyone(stmt) { as_array(stmt.Principal)[_] == "*" }
applies_to_everyone(stmt) { as_array(stmt.Principal.AWS)[_] == "*" }

# The payload does not name the endpoint's partition, so any of these counts.
partitions := {"aws", "aws-cn", "aws-us-gov"}

covers_every_object(stmt) {
    tocm_s3_pattern_covers_all_objects(as_array(stmt.Resource)[_], partitions[_])
}

# A statement with a Not element leaves something out and never counts.
negated_elements := {"NotPrincipal", "NotAction", "NotResource"}

uses_negation(stmt) {
    negated_elements[k]
    object.get(stmt, k, null) != null
}

full_scope_deny(stmt) {
    stmt.Effect == "Deny"
    not uses_negation(stmt)
    applies_to_everyone(stmt)
    covers_every_object(stmt)
}

# Each header test must be the only condition: two keys deny only requests
# with both. Operator names are case sensitive; key names are not.
conditions(stmt) := [{"operator": op, "key": lower(key), "values": as_array(v)} | v := stmt.Condition[op][key]]

sole_condition(stmt) := c {
    cs := conditions(stmt)
    count(cs) == 1
    c := cs[0]
}

# Canned ACLs that let anyone, or any AWS account, read the object.
public_canned_acls := {"public-read", "public-read-write", "authenticated-read"}

canned_acl_operators := {"StringEquals", "StringEqualsIfExists"}

# A canned ACL is one token, so a pattern covers each ACL it matches.
canned_acl_pattern_operators := {"StringLike", "StringLikeIfExists"}

# Grant headers, and the groups whose grant makes an object public.
grant_headers := {
    "s3:x-amz-grant-read",
    "s3:x-amz-grant-read-acp",
    "s3:x-amz-grant-write-acp",
    "s3:x-amz-grant-full-control",
}

public_groups := {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}

grant_operators := {"StringLike", "StringLikeIfExists"}

# A grant header lists comma-separated grantees, so only a pattern with "*" at
# both ends covers the group URI wherever it sits.
pattern_covers_group(p, uri) {
    is_string(p)
    startswith(p, "*")
    endswith(p, "*")
    tocm_iam_pattern_matches(p, uri)
}

# Every pairing of action and header value the policy must deny.
required[r] {
    action := acl_actions[_]
    acl := public_canned_acls[_]
    r := {"action": action, "key": "s3:x-amz-acl", "value": acl}
}

required[r] {
    action := acl_actions[_]
    header := grant_headers[_]
    public_groups[uri]
    r := {"action": action, "key": header, "value": uri}
}

condition_covers(c, value) {
    c.key == "s3:x-amz-acl"
    canned_acl_operators[c.operator]
    c.values[_] == value
}

condition_covers(c, value) {
    c.key == "s3:x-amz-acl"
    canned_acl_pattern_operators[c.operator]
    tocm_iam_pattern_matches(c.values[_], value)
}

condition_covers(c, uri) {
    grant_headers[c.key]
    grant_operators[c.operator]
    pattern_covers_group(c.values[_], uri)
}

# Null "false" denies every request that carries the header, whatever it names.
condition_covers(c, _) {
    grant_headers[c.key]
    c.operator == "Null"
    is_false(c.values[_])
}

is_false(v) { v == false }

is_false(v) {
    is_string(v)
    lower(v) == "false"
}

# Qualifying denies may split the actions, headers and values between them.
covered[r] {
    stmt := statements[_]
    full_scope_deny(stmt)
    c := sole_condition(stmt)
    r := required[_]
    r.key == c.key
    covers_action(stmt, r.action)
    condition_covers(c, r.value)
}

# A deny with no condition blocks every ACL write of the actions it covers.
covered[r] {
    stmt := statements[_]
    full_scope_deny(stmt)
    count(conditions(stmt)) == 0
    r := required[_]
    covers_action(stmt, r.action)
}

missing := required - covered

describe(r) := sprintf("%s with %s %s", [r.action, r.key, r.value]) {
    r.key == "s3:x-amz-acl"
} else := sprintf("%s with %s naming %s", [r.action, r.key, public_groups[r.value]])

missing_list := concat(", ", sort([describe(r) | r := missing[_]]))

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    count(missing) > 0
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so it does not block setting object ACLs to public." {
    result == "fail"
    input.PolicyDocument == null
} else := "VPC endpoint policy has no Deny for all principals on every object that blocks a public canned ACL or a public grant header." {
    result == "fail"
    count(covered) == 0
} else := sprintf("VPC endpoint policy does not deny, for all principals on every object with that test as the only condition: %s", [missing_list]) {
    result == "fail"
} else := "VPC endpoint policy denies every public canned ACL and public grant header on object ACL writes."

expectedConfiguration := "S3 VPC endpoint policy must Deny s3:PutObjectAcl and s3:PutObjectVersionAcl for all principals on every object when s3:x-amz-acl is public-read, public-read-write or authenticated-read (StringEquals, or a StringLike pattern that matches the value), and when s3:x-amz-grant-read, s3:x-amz-grant-read-acp, s3:x-amz-grant-write-acp or s3:x-amz-grant-full-control names the AllUsers or AuthenticatedUsers group (StringLike, for example \"*http://acs.amazonaws.com/groups/global/AllUsers*\", or Null false), each header in its own statement; a Deny with no condition covers everything. Only request headers are checked: an ACL sent in the request body is not shown to be denied."

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
