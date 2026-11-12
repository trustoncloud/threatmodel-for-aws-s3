package wiz

# --- Logic ---
default result := "pass"

# The bucket policy arrives as a JSON string at input.bucketPolicy.
policy_doc := doc {
    is_string(input.bucketPolicy)
    doc := json.unmarshal(input.bucketPolicy)
} else := doc {
    is_object(input.bucketPolicy)
    doc := input.bucketPolicy
}

# Only judge when Wiz successfully fetched the bucket policy; null with a
# fetch error means unreadable, not absent.
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

# The deny must cover all S3 actions to block traffic comprehensively.
covers_all_s3(action) { action == "s3:*" }
covers_all_s3(action) { action == "*" }
covers_all_s3(action) { action[_] == "s3:*" }
covers_all_s3(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

# The deny must apply to every principal.
applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The deny must reach the bucket itself and every object in it.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

scope_targets := {"bucket", "objects"}

as_array(v) := v { is_array(v) } else := [v]

# A Resource pattern reaches the bucket when it matches the bucket ARN, and
# the objects only when it leaves no key out.
resource_covers(stmt, "bucket") {
    tocm_iam_pattern_matches(as_array(stmt.Resource)[_], bucket_arn)
}

resource_covers(stmt, "objects") {
    tocm_s3_pattern_covers_objects(as_array(stmt.Resource)[_], bucket_arn)
}

# A statement written with NotResource, NotAction or NotPrincipal is never
# counted as the covering deny.
uses_not_element(stmt) {
    _ = stmt[{"NotResource", "NotAction", "NotPrincipal"}[_]]
}

secure_transport_false(v) { v == "false" }
secure_transport_false(v) { v == false }
secure_transport_false(v) { v[_] == "false" }

tls_floor_ok(v) { to_number(v) >= 1.2 }
tls_floor_ok(v) { to_number(v[_]) >= 1.2 }

# The transport test must be the only condition; any extra key narrows the deny.
sole_condition(stmt, operator) {
    count(stmt.Condition) == 1
    count(stmt.Condition[operator]) == 1
}

scoped_deny(stmt) {
    stmt.Effect == "Deny"
    not uses_not_element(stmt)
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
}

denies_insecure_transport(stmt) {
    scoped_deny(stmt)
    sole_condition(stmt, "Bool")
    secure_transport_false(stmt.Condition.Bool["aws:SecureTransport"])
}

denies_unauthorized_tls(stmt) {
    scoped_deny(stmt)
    sole_condition(stmt, "NumericLessThan")
    tls_floor_ok(stmt.Condition.NumericLessThan["s3:TlsVersion"])
}

# Qualifying denies may split the bucket and its objects across statements.
transport_scope[target] {
    stmt := statements[_]
    denies_insecure_transport(stmt)
    target := scope_targets[_]
    resource_covers(stmt, target)
}

tls_scope[target] {
    stmt := statements[_]
    denies_unauthorized_tls(stmt)
    target := scope_targets[_]
    resource_covers(stmt, target)
}

has_secure_transport_deny {
    count(transport_scope) == count(scope_targets)
}

has_tls_floor_deny {
    count(tls_scope) == count(scope_targets)
}

# Both protections are required; missing either one is non-compliant.
result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_secure_transport_deny
} else := "fail" {
    not has_tls_floor_deny
}

# --- Metadata ---
missing_protections[p] {
    not has_secure_transport_deny
    p := "a Deny of unencrypted requests (aws:SecureTransport false)"
}

missing_protections[p] {
    not has_tls_floor_deny
    p := "a Deny of TLS versions below 1.2 (s3:TlsVersion)"
}

currentConfiguration := "Bucket has no bucket policy, so nothing blocks unencrypted requests or old TLS versions." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy lacks %s. Each Deny must apply to all principals and all S3 actions on the bucket and every object in it, with no other condition.", [concat(" and ", [p | p := missing_protections[_]])]) {
    result == "fail"
} else := "Bucket policy denies unencrypted requests and TLS versions below 1.2 for all principals on the bucket and every object in it."

expectedConfiguration := "Bucket policy must contain a Deny statement for all principals and all S3 actions on the bucket and every object in it when aws:SecureTransport is false, and another when s3:TlsVersion is below 1.2. Each must carry no other condition."

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
