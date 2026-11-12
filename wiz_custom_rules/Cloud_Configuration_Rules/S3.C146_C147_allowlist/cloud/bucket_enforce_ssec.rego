package wiz

# --- Configuration ---
# Buckets that must enforce SSE-C on PutObject: a bucket name for the whole
# bucket, or "bucket/prefix/" for one path inside it.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
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

# Paths of this bucket that require SSE-C; "" stands for the whole bucket.
required_prefixes[prefix] {
    buckets_requiring_ssec[input.Name]
    prefix := ""
}

required_prefixes[prefix] {
    entry := buckets_requiring_ssec[_]
    startswith(entry, concat("", [input.Name, "/"]))
    path := trim_suffix(trim_prefix(entry, concat("", [input.Name, "/"])), "/")
    path != ""
    prefix := concat("", [path, "/"])
}

is_required_bucket {
    count(required_prefixes) > 0
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

value_is(v, target) { v == target }
value_is(v, target) { v[_] == target }

bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

# Every key under a required path starts with this; "" is the whole bucket.
path_base(prefix) := concat("", [bucket_arn, "/", prefix])

as_array(v) := v { is_array(v) } else := [v]

# A statement written with NotResource, NotAction or NotPrincipal is never
# counted as the covering deny.
uses_not_element(stmt) {
    _ = stmt[{"NotResource", "NotAction", "NotPrincipal"}[_]]
}

ssec_key := "s3:x-amz-server-side-encryption-customer-algorithm"

# The SSE-C test must be the only condition: a StringNotEquals AES256 or a
# Null true on the customer-algorithm header.
enforcing_condition(stmt) {
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    {"stringnotequals", "stringnotequalsifexists"}[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == ssec_key
    value_is(val, "AES256")
}

enforcing_condition(stmt) {
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    lower(operator) == "null"
    count(conditions) == 1
    val := conditions[key]
    lower(key) == ssec_key
    value_is(val, "true")
}

enforced_prefixes[prefix] {
    stmt := statements[_]
    stmt.Effect == "Deny"
    not uses_not_element(stmt)
    covers_put_object(stmt.Action)
    applies_to_everyone(stmt.Principal)
    enforcing_condition(stmt)
    prefix := required_prefixes[_]
    covers_path(as_array(stmt.Resource)[_], prefix)
}

# The whole bucket: an object key is never empty, so "/?*" reaches every
# object. A path stays strict: the key that names the path is an object too.
covers_path(p, prefix) {
    prefix == ""
    tocm_s3_pattern_covers_objects(p, bucket_arn)
}

covers_path(p, prefix) {
    prefix != ""
    tocm_iam_pattern_covers_prefix(p, path_base(prefix))
}

missing_prefixes := required_prefixes - enforced_prefixes

result := "skip" {
    not fetch_ok
} else := "pass" {
    not is_required_bucket
} else := "fail" {
    count(missing_prefixes) > 0
}

# --- Metadata ---
path_label(prefix) := "the whole bucket" { prefix == "" } else := prefix

currentConfiguration := sprintf("Bucket requires SSE-C on %s but its policy does not enforce it there for all principals on PutObject, with no other condition.", [concat(", ", sort([path_label(p) | p := missing_prefixes[_]]))]) {
    result == "fail"
} else := "Bucket enforces SSE-C on its required paths, or is not required to."

expectedConfiguration := "Buckets and paths in the required set must Deny s3:PutObject for all principals when s3:x-amz-server-side-encryption-customer-algorithm is missing (Null true) or not AES256 (StringNotEquals), with no other condition."

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
