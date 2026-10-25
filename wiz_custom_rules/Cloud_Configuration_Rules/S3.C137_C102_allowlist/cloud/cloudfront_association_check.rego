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

oai_principals(statement) := {p | p := statement.Principal.AWS; is_string(p)} {
    is_string(statement.Principal.AWS)
} else := {p | p := statement.Principal.AWS[_]}

# Legacy OAI association: Allow to a CloudFront origin access identity principal.
is_oai_statement(statement) {
    statement.Effect == "Allow"
    p := oai_principals(statement)[_]
    contains(lower(p), "cloudfront")
}

# Modern OAC association: Allow to the cloudfront.amazonaws.com service principal.
is_oac_statement(statement) {
    statement.Effect == "Allow"
    statement.Principal.Service == "cloudfront.amazonaws.com"
}

is_oac_statement(statement) {
    statement.Effect == "Allow"
    statement.Principal.Service[_] == "cloudfront.amazonaws.com"
}

oai_authorized(statement) {
    p := oai_principals(statement)[_]
    contains(lower(p), "cloudfront")
    id := authorized_cloudfront_ids[_]
    contains(p, id)
}

source_arn_values(statement) := v {
    conditions := statement.Condition[operator]
    contains(lower(operator), "equals")
    v := conditions[key]
    lower(key) == "aws:sourcearn"
} else := v {
    conditions := statement.Condition[operator]
    contains(lower(operator), "arnlike")
    v := conditions[key]
    lower(key) == "aws:sourcearn"
}

oac_authorized(statement) {
    v := source_arn_values(statement)
    is_string(v)
    id := authorized_cloudfront_ids[_]
    contains(v, id)
}

oac_authorized(statement) {
    v := source_arn_values(statement)[_]
    id := authorized_cloudfront_ids[_]
    contains(v, id)
}

has_unauthorized_association {
    statement := statements[_]
    is_oai_statement(statement)
    not oai_authorized(statement)
}

has_unauthorized_association {
    statement := statements[_]
    is_oac_statement(statement)
    not oac_authorized(statement)
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    has_unauthorized_association
}

# --- Metadata ---
currentConfiguration := "Bucket policy grants CloudFront access to an unauthorized distribution or identity." {
    result == "fail"
} else := "Bucket restricts CloudFront access to authorized distributions and identities, or has no CloudFront association."

expectedConfiguration := sprintf("CloudFront statements must reference only authorized IDs via the OAI principal or the aws:SourceArn condition: %v", [authorized_cloudfront_ids])
