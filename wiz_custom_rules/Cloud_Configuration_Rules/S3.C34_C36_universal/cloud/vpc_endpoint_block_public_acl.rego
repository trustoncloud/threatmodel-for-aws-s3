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

# The deny must cover s3:PutObjectAcl, by name or by a pattern that matches it.
# An upload that sets an ACL needs s3:PutObjectAcl as well, so the deny also
# stops uploads with a public canned ACL.
covers_put_object_acl(stmt) {
    tocm_iam_pattern_matches(lower(as_array(stmt.Action)[_]), "s3:putobjectacl")
}

# The deny must apply to every principal.
applies_to_everyone(stmt) { as_array(stmt.Principal)[_] == "*" }
applies_to_everyone(stmt) { as_array(stmt.Principal.AWS)[_] == "*" }

# The endpoint reaches every bucket, so the deny must cover every object. The
# endpoint payload does not name its partition, so a pattern for any of these
# partitions counts.
partitions := {"aws", "aws-cn", "aws-us-gov"}

covers_every_object(stmt) {
    tocm_s3_pattern_covers_all_objects(as_array(stmt.Resource)[_], partitions[_])
}

# A statement written with NotPrincipal, NotAction or NotResource leaves
# something out, so it never counts.
negated_elements := {"NotPrincipal", "NotAction", "NotResource"}

uses_negation(stmt) {
    negated_elements[k]
    object.get(stmt, k, null) != null
}

# The canned ACL test must be the only condition; any extra key narrows the deny.
conditions(stmt) := [{"operator": lower(op), "key": lower(key), "values": as_array(v)} | v := stmt.Condition[op][key]]

sole_condition(stmt) := c {
    cs := conditions(stmt)
    count(cs) == 1
    c := cs[0]
}

public_acls := {"public-read", "public-read-write"}

acl_operators := {"stringequals", "stringequalsifexists"}

# A Deny of s3:PutObjectAcl for all principals on every object, with the
# canned ACL test as its one condition.
acl_deny(stmt) := c {
    stmt.Effect == "Deny"
    not uses_negation(stmt)
    applies_to_everyone(stmt)
    covers_put_object_acl(stmt)
    covers_every_object(stmt)
    c := sole_condition(stmt)
    acl_operators[c.operator]
    c.key == "s3:x-amz-acl"
}

# Qualifying denies may split the two public canned ACLs between them.
blocked_acls[v] {
    c := acl_deny(statements[_])
    v := c.values[_]
}

missing_acls := public_acls - blocked_acls

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    count(missing_acls) > 0
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so it does not block setting object ACLs to public." {
    result == "fail"
    input.PolicyDocument == null
} else := sprintf("VPC endpoint policy has no Deny of s3:PutObjectAcl for all principals on all objects, with no other condition, for the canned ACL(s): %v", [missing_acls]) {
    result == "fail"
} else := "VPC endpoint policy blocks setting object ACLs to public."

expectedConfiguration := "S3 VPC endpoint policy must Deny s3:PutObjectAcl for all principals on all objects when s3:x-amz-acl is public-read or public-read-write (StringEquals), with no other condition."

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
