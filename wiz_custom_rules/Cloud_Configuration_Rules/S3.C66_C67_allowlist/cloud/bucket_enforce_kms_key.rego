package wiz

# --- Configuration ---
authorized_kms_key_ids := {
    "arn:aws:kms:us-east-1:123456789012:key/authorized-key",
}

# --- Logic ---
default result := "pass"

policy_doc := doc {
    is_string(input.bucketPolicy)
    doc := json.unmarshal(input.bucketPolicy)
} else := doc {
    is_object(input.bucketPolicy)
    doc := input.bucketPolicy
}

fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketPolicy.result == "Success"
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

covers_put_object(action) { action == "s3:PutObject" }
covers_put_object(action) { action == "s3:*" }
covers_put_object(action) { action == "*" }
covers_put_object(action) { action[_] == "s3:PutObject" }
covers_put_object(action) { action[_] == "s3:*" }
covers_put_object(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The deny must reach every object in the bucket.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

as_array(v) := v { is_array(v) } else := [v]

# A statement written with NotResource, NotAction or NotPrincipal is never
# counted as the covering deny.
uses_not_element(stmt) {
    _ = stmt[{"NotResource", "NotAction", "NotPrincipal"}[_]]
}

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

# A Deny on PutObject for everyone on every object whose only condition is a
# StringNotEquals on the KMS key header, listing only authorized keys.
enforces_authorized_key {
    statement := statements[_]
    statement.Effect == "Deny"
    not uses_not_element(statement)
    covers_put_object(statement.Action)
    applies_to_everyone(statement.Principal)
    tocm_s3_pattern_covers_objects(as_array(statement.Resource)[_], bucket_arn)
    count(statement.Condition) == 1
    conditions := statement.Condition[operator]
    restriction_operators[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "s3:x-amz-server-side-encryption-aws-kms-key-id"
    vals := {v | v := as_array(val)[_]}
    count(vals) > 0
    count(vals - authorized_kms_key_ids) == 0
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    not enforces_authorized_key
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so PutObject requests with any KMS key are accepted." {
    result == "fail"
    input.bucketPolicy == null
} else := "Bucket policy has no Deny restricting PutObject to the authorized KMS key(s) for all principals on every object, with no other condition." {
    result == "fail"
} else := "Bucket policy enforces the authorized KMS key(s) for PutObject."

expectedConfiguration := sprintf("Bucket policy must Deny s3:PutObject for all principals on every object when s3:x-amz-server-side-encryption-aws-kms-key-id is not in the authorized set, with no other condition: %v", [authorized_kms_key_ids])

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
