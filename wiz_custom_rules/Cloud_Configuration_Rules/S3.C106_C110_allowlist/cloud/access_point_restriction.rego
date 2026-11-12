package wiz

# --- Configuration ---
authorized_access_points := {
    "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap",
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

covers_all_s3(action) { action == "s3:*" }
covers_all_s3(action) { action == "*" }
covers_all_s3(action) { action[_] == "s3:*" }
covers_all_s3(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The deny must reach every object in the bucket: one Resource pattern must
# leave no key out. Covering the bucket ARN as well is accepted but not
# required, since bucket settings calls cannot go through an access point.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

as_array(v) := v { is_array(v) } else := [v]

covers_every_object(stmt) {
    tocm_s3_pattern_covers_objects(as_array(stmt.Resource)[_], bucket_arn)
}

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

# A Deny for everyone on all S3 actions whose only condition is a
# StringNotEquals on s3:DataAccessPointArn allows exactly the listed access
# points.
ap_condition_values(stmt) := vals {
    stmt.Effect == "Deny"
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    restriction_operators[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "s3:dataaccesspointarn"
    vals := as_array(val)
}

allowed_by_policy[ap] {
    ap := ap_condition_values(statements[_])[_]
}

has_ap_restriction {
    stmt := statements[_]
    ap_condition_values(stmt)
    covers_every_object(stmt)
}

unauthorized_aps := allowed_by_policy - authorized_access_points

result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_ap_restriction
} else := "fail" {
    count(unauthorized_aps) > 0
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so access points are not restricted." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy allows unauthorized access point(s): %v", [unauthorized_aps]) {
    result == "fail"
    count(unauthorized_aps) > 0
} else := "Bucket policy has no access point restriction that applies to all principals and all S3 actions on every object, with no other condition." {
    result == "fail"
} else := "Bucket policy restricts access to authorized access points."

expectedConfiguration := sprintf("Bucket policy must contain a Deny for all principals and all S3 actions on every object in the bucket whose only condition is StringNotEquals on s3:DataAccessPointArn, listing only authorized access points: %v", [authorized_access_points])

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
