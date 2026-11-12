package wiz

# --- Configuration ---
# Authorized CloudFront distribution IDs (OAC) and origin access identity IDs (OAI).
authorized_cloudfront_ids := {
    "E2AUTHORIZED12345",
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

as_array(v) := v { is_array(v) } else := [v]

principal_values(stmt, kind) := as_array(stmt.Principal[kind]) {
    is_object(stmt.Principal)
} else := []

# Legacy OAI association: the principal is an identity of the "cloudfront"
# account, written "arn:aws:iam::cloudfront:user/CloudFront Origin Access
# Identity <ID>".
is_oai_principal(p) {
    parts := tocm_arn_parts(p)
    parts.service == "iam"
    parts.account == "cloudfront"
}

oai_approved(p) {
    tocm_arn_parts(p).resource == sprintf("user/CloudFront Origin Access Identity %s", [authorized_cloudfront_ids[_]])
}

# Modern OAC association: the cloudfront.amazonaws.com service principal,
# limited to a distribution by aws:SourceArn.
is_oac_statement(stmt) {
    lower(principal_values(stmt, "Service")[_]) == "cloudfront.amazonaws.com"
}

# Only these operators limit the grant to the listed values.
source_arn_operators := {"StringEquals", "StringEqualsIfExists", "ArnEquals", "ArnEqualsIfExists", "ArnLike", "ArnLikeIfExists"}

# The values of each aws:SourceArn test the statement carries.
source_arn_tests(stmt) := [values |
    values := as_array(stmt.Condition[operator][key])
    source_arn_operators[operator]
    lower(key) == "aws:sourcearn"
]

# A value is approved when it is the ARN of an approved distribution, with no
# wildcard in it.
distribution_approved(v) {
    not regex.match(`[*?]`, v)
    parts := tocm_arn_parts(v)
    parts.service == "cloudfront"
    parts.region == ""
    parts.resource == sprintf("distribution/%s", [authorized_cloudfront_ids[_]])
}

unapproved_values(values) := [v | v := values[_]; not distribution_approved(v)]

# One test must hold approved distributions only; the values of a test are
# alternatives, so one that is not approved opens the grant to it.
oac_authorized(stmt) {
    values := source_arn_tests(stmt)[_]
    count(values) > 0
    count(unapproved_values(values)) == 0
}

unapproved_associations[msg] {
    stmt := statements[_]
    stmt.Effect == "Allow"
    p := principal_values(stmt, "AWS")[_]
    is_oai_principal(p)
    not oai_approved(p)
    msg := sprintf("origin access identity '%v'", [p])
}

unapproved_associations[msg] {
    stmt := statements[_]
    stmt.Effect == "Allow"
    is_oac_statement(stmt)
    not oac_authorized(stmt)
    v := unapproved_values(source_arn_tests(stmt)[_])[_]
    msg := sprintf("aws:SourceArn '%v'", [v])
}

unapproved_associations[msg] {
    stmt := statements[_]
    stmt.Effect == "Allow"
    is_oac_statement(stmt)
    count(source_arn_tests(stmt)) == 0
    msg := "the CloudFront service with no aws:SourceArn test that uses StringEquals, ArnEquals or ArnLike"
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    count(unapproved_associations) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket policy grants CloudFront access that is not approved: %s.", [concat("; ", sort(unapproved_associations))]) {
    result == "fail"
} else := "Bucket restricts CloudFront access to authorized distributions and identities, or has no CloudFront association."

expectedConfiguration := sprintf("Every CloudFront statement must name only authorized IDs: an origin access identity principal, or the cloudfront.amazonaws.com service limited by aws:SourceArn (StringEquals, ArnEquals or ArnLike, no wildcard) to authorized distributions: %v", [authorized_cloudfront_ids])

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
