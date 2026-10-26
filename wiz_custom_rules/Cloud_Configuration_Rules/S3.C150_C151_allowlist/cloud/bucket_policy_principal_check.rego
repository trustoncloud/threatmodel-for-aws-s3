package wiz

# --- Configuration ---
authorized_principals := {
    "arn:aws:iam::123456789012:role/authorized-role",
    "arn:aws:iam::123456789012:root",
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

# IAM principals granted access by Allow statements. Service principals are
# out of scope for this control.
granted_principals[principal] {
    statement := statements[_]
    statement.Effect == "Allow"
    is_string(statement.Principal.AWS)
    principal := statement.Principal.AWS
}

granted_principals[principal] {
    statement := statements[_]
    statement.Effect == "Allow"
    principal := statement.Principal.AWS[_]
}

granted_principals["*"] {
    statement := statements[_]
    statement.Effect == "Allow"
    statement.Principal == "*"
}

unauthorized_principals := granted_principals - authorized_principals

result := "skip" {
    not fetch_ok
} else := "fail" {
    count(unauthorized_principals) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket policy grants access to unauthorized principal(s): %v", [unauthorized_principals]) {
    result == "fail"
} else := "Bucket policy grants access only to authorized principals, or grants no IAM principal access."

expectedConfiguration := sprintf("Allow statements in the bucket policy must only grant access to authorized IAM principals: %v", [authorized_principals])
