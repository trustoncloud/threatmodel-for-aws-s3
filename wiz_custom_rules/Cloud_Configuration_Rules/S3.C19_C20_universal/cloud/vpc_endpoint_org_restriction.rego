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

# The deny must cover all S3 actions.
all_s3_actions := {"*", "s3:*"}

covers_all_actions(stmt) {
    all_s3_actions[lower(as_array(stmt.Action)[_])]
}

# The deny must apply to every principal.
applies_to_everyone(stmt) { as_array(stmt.Principal)[_] == "*" }
applies_to_everyone(stmt) { as_array(stmt.Principal.AWS)[_] == "*" }

# The endpoint reaches every bucket, so the deny must cover every bucket and
# every object. The endpoint payload does not name its partition, so a pattern
# for any of these partitions counts.
partitions := {"aws", "aws-cn", "aws-us-gov"}

covers_every_bucket_and_object(stmt) {
    tocm_s3_pattern_covers_all(as_array(stmt.Resource)[_], partitions[_])
}

# A statement written with NotPrincipal, NotAction or NotResource leaves
# something out, so it never counts.
negated_elements := {"NotPrincipal", "NotAction", "NotResource"}

uses_negation(stmt) {
    negated_elements[k]
    object.get(stmt, k, null) != null
}

full_scope_deny(stmt) {
    stmt.Effect == "Deny"
    not uses_negation(stmt)
    applies_to_everyone(stmt)
    covers_all_actions(stmt)
    covers_every_bucket_and_object(stmt)
}

# The organization test must be the only condition; any extra key narrows the deny.
conditions(stmt) := [{"operator": lower(op), "key": lower(key), "values": as_array(v)} | v := stmt.Condition[op][key]]

sole_condition(stmt) := c {
    cs := conditions(stmt)
    count(cs) == 1
    c := cs[0]
}

# Operators that make the Deny apply to every principal outside the listed
# values, by condition key. aws:PrincipalOrgID and aws:PrincipalAccount hold
# one value. aws:PrincipalOrgPaths holds a set, so it needs ForAllValues: a
# principal outside any organization has no paths, ForAllValues is then true
# and the Deny applies, while a ForAnyValue condition is then false.
org_key_operators := {
    "aws:principalorgid": {"stringnotequals", "stringnotequalsifexists"},
    "aws:principalaccount": {"stringnotequals", "stringnotequalsifexists"},
    "aws:principalorgpaths": {"forallvalues:stringnotequals", "forallvalues:stringnotlike"},
}

# The policy restricts by organization when a full-scope Deny carries an org
# condition. This mode does not check the specific values.
has_org_restriction {
    stmt := statements[_]
    full_scope_deny(stmt)
    c := sole_condition(stmt)
    org_key_operators[c.key][c.operator]
    is_string(c.values[_])
}

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    not has_org_restriction
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so access is not restricted by organization." {
    result == "fail"
    input.PolicyDocument == null
} else := "VPC endpoint policy has no Deny that restricts access by organization for all principals and all S3 actions on all buckets and objects, with the organization test as its only condition." {
    result == "fail"
} else := "VPC endpoint policy restricts access by organization."

expectedConfiguration := "S3 VPC endpoint policy must contain a Deny for all principals and all S3 actions on all buckets and objects, with StringNotEquals or StringNotEqualsIfExists on aws:PrincipalOrgID or aws:PrincipalAccount, or ForAllValues:StringNotEquals or ForAllValues:StringNotLike on aws:PrincipalOrgPaths, as its only condition."

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
