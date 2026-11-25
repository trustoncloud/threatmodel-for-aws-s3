package wiz

# --- Configuration ---
# Roles a bucket policy Deny may exempt, by full ARN. Each is authorized on
# every assessed bucket, so list only the service-linked roles that need the
# buckets (such as Amazon Macie). Every role a Deny exempts must be listed.
authorized_service_roles := {
    "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
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

# IAM action names are not case sensitive, so they are compared in lower case.
all_s3_actions := {"s3:*", "*"}

covers_all_s3(action) {
    is_string(action)
    all_s3_actions[lower(action)]
}

covers_all_s3(action) {
    a := action[_]
    is_string(a)
    all_s3_actions[lower(a)]
}

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The deny must reach the bucket itself and every object in it.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

bucket_partition := tocm_arn_parts(bucket_arn).partition

scope_targets := {"bucket", "objects"}

as_array(v) := v { is_array(v) } else := [v]

# A pattern reaches the objects only when it leaves no key out.
resource_covers(stmt, "bucket") {
    tocm_iam_pattern_matches(as_array(stmt.Resource)[_], bucket_arn)
}

resource_covers(stmt, "objects") {
    tocm_s3_pattern_covers_objects(as_array(stmt.Resource)[_], bucket_arn)
}

# A Deny written with NotResource, NotAction or NotPrincipal never counts.
uses_not_element(stmt) {
    _ = stmt[{"NotResource", "NotAction", "NotPrincipal"}[_]]
}

# --- Service-linked roles ---
# A like value counts only if it reaches every service-linked role in the
# partition: any account, and all of role/aws-service-role/ or a form below.
slr_resource_forms := {
    "*/AWSServiceRoleFor*",
    "*AWSServiceRoleFor*",
    "role/*/AWSServiceRoleFor*",
    "role/*AWSServiceRoleFor*",
    "role/aws-service-role/*/AWSServiceRoleFor*",
    "role/aws-service-role/*AWSServiceRoleFor*",
}

slr_resource_covered(r) {
    tocm_iam_pattern_covers_prefix(r, "role/aws-service-role/")
}

slr_resource_covered(r) {
    slr_resource_forms[r]
}

# Operators naming the roles the Deny applies to. ArnEquals acts as ArnLike.
# Operator names match exactly.
like_operators := {"ArnLike", "ArnLikeIfExists", "ArnEquals", "ArnEqualsIfExists", "StringLike", "StringLikeIfExists"}

arn_operators := {"ArnLike", "ArnLikeIfExists", "ArnEquals", "ArnEqualsIfExists"}

# Operators that exempt roles from the Deny.
exempt_operators := {
    "ArnNotEquals", "ArnNotEqualsIfExists", "ArnNotLike", "ArnNotLikeIfExists",
    "StringNotEquals", "StringNotEqualsIfExists", "StringNotLike", "StringNotLikeIfExists",
}

# An account ID has twelve digits. A part of "?" and "*" covers every ID with
# exactly twelve "?", or with at most twelve "?" and a "*".
account_covers_all(a) {
    is_string(a)
    regex.match(`^[?]{12}$`, a)
}

account_covers_all(a) {
    is_string(a)
    regex.match(`^[?*]+$`, a)
    contains(a, "*")
    count(replace(a, "*", "")) <= 12
}

# ArnLike and ArnEquals compare the six ARN parts one by one.
like_value_covers_slrs(op, v, partition) {
    arn_operators[op]
    p := tocm_arn_parts(v)
    {partition, "*"}[p.partition]
    {"iam", "*"}[p.service]
    {"", "*"}[p.region]
    account_covers_all(p.account)
    slr_resource_covered(p.resource)
}

# StringLike reads the whole value, where "*" also spans ":".
like_value_covers_slrs(op, v, partition) {
    not arn_operators[op]
    tocm_iam_pattern_covers_prefix(v, concat("", ["arn:", partition, ":iam::"]))
}

like_value_covers_slrs(op, v, partition) {
    not arn_operators[op]
    is_string(v)
    part := {partition, "*"}[_]
    prefix := concat("", ["arn:", part, ":iam::"])
    startswith(v, prefix)
    rest := substring(v, count(prefix), -1)
    i := indexof(rest, ":")
    i > 0
    account_covers_all(substring(rest, 0, i))
    slr_resource_covered(substring(rest, i + 1, -1))
}

# Values of an operator whose only key is aws:PrincipalArn.
principal_arn_values(stmt, operator) := vals {
    conditions := stmt.Condition[operator]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "aws:principalarn"
    vals := as_array(val)
}

# Any condition other than one on aws:PrincipalArn alone narrows the Deny.
has_other_condition(stmt) {
    stmt.Condition[operator]
    not principal_arn_operator(stmt, operator)
}

principal_arn_operator(stmt, operator) {
    like_operators[operator]
    principal_arn_values(stmt, operator)
}

principal_arn_operator(stmt, operator) {
    exempt_operators[operator]
    principal_arn_values(stmt, operator)
}

# One value of the operator must cover every service-linked role.
operator_covers_slrs(stmt, operator) {
    p := principal_arn_values(stmt, operator)[_]
    like_value_covers_slrs(operator, p, bucket_partition)
}

# Like operators combine with AND, so each must reach every role.
misses_some_slr(stmt) {
    stmt.Condition[operator]
    like_operators[operator]
    not operator_covers_slrs(stmt, operator)
}

# With no like operator, the Deny reaches every principal it does not exempt.
blocks_service_linked_roles(stmt) {
    stmt.Effect == "Deny"
    not uses_not_element(stmt)
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
    not has_other_condition(stmt)
    not misses_some_slr(stmt)
}

restricted_scope[target] {
    stmt := statements[_]
    blocks_service_linked_roles(stmt)
    target := scope_targets[_]
    resource_covers(stmt, target)
}

exempted_roles[role] {
    stmt := statements[_]
    blocks_service_linked_roles(stmt)
    stmt.Condition[operator]
    exempt_operators[operator]
    role := principal_arn_values(stmt, operator)[_]
}

has_role_restriction {
    count(restricted_scope) == count(scope_targets)
}

unauthorized_roles := {role |
    role := exempted_roles[_]
    not tocm_arn_allowed(role, authorized_service_roles)
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_role_restriction
} else := "fail" {
    count(unauthorized_roles) > 0
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so service-linked roles are not blocked." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy exempts unauthorized role(s) from the deny: %v", [unauthorized_roles]) {
    result == "fail"
    count(unauthorized_roles) > 0
} else := "Bucket policy has no Deny for all principals and all S3 actions on the bucket and every object in it that reaches every service-linked role, with aws:PrincipalArn as its only condition key." {
    result == "fail"
} else := "Bucket policy blocks every service-linked role except authorized ones."

expectedConfiguration := sprintf("Bucket policy must contain a Deny for all principals and all S3 actions on the bucket and every object in it that reaches every service-linked role, with aws:PrincipalArn as its only condition key: an ArnLike or StringLike pattern matching every account that covers every role under role/aws-service-role/ or named AWSServiceRoleFor, in the bucket's partition or * (such as arn:aws:iam::*:role/aws-service-role/*), or no pattern so the Deny reaches every principal. Roles it exempts with ArnNotEquals, ArnNotLike, StringNotEquals or StringNotLike must be authorized: %v", [authorized_service_roles])

# --- Matching helpers ---
# --- toc-match begin: arn v1 ---
# Parts of an AWS ARN; the resource keeps any further ":" characters.
tocm_arn_parts(arn) := {"partition": s[1], "service": s[2], "region": s[3], "account": s[4], "resource": r} {
    is_string(arn)
    s := split(trim_space(arn), ":")
    count(s) >= 6
    s[0] == "arn"
    s[1] != ""
    s[2] != ""
    r := concat(":", array.slice(s, 5, count(s)))
    r != ""
}

tocm_arn_equal(a, b) {
    tocm_arn_parts(a) == tocm_arn_parts(b)
}

tocm_arn_allowed(arn, allowed) {
    tocm_arn_equal(arn, allowed[_])
}

# Bucket name of an S3 bucket or object ARN (arn:aws:s3:::bucket[/key]).
tocm_s3_arn_bucket(arn) := b {
    p := tocm_arn_parts(arn)
    p.service == "s3"
    p.region == ""
    p.account == ""
    b := split(p.resource, "/")[0]
    b != ""
}
# --- toc-match end: arn v1 ---

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
