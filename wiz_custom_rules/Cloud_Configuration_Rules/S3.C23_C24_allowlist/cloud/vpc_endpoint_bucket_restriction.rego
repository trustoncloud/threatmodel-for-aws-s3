package wiz

# --- Configuration ---
# S3 bucket ARNs the endpoint may grant access to.
authorized_buckets := {
    "arn:aws:s3:::authorized-bucket",
}

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

resource_authorized(res) {
    authorized_buckets[res]
}

resource_authorized(res) {
    endswith(res, "/*")
    base := substring(res, 0, count(res) - 2)
    authorized_buckets[base]
}

allowed_resources[res] {
    statement := statements[_]
    statement.Effect == "Allow"
    is_string(statement.Resource)
    res := statement.Resource
}

allowed_resources[res] {
    statement := statements[_]
    statement.Effect == "Allow"
    res := statement.Resource[_]
}

unauthorized_resources[res] {
    allowed_resources[res]
    not resource_authorized(res)
}

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    count(unauthorized_resources) > 0
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so it can access any bucket." {
    result == "fail"
    input.PolicyDocument == null
} else := sprintf("VPC endpoint allows access to unauthorized resource(s): %v", [unauthorized_resources]) {
    result == "fail"
} else := "VPC endpoint restricts access to authorized buckets."

expectedConfiguration := sprintf("S3 VPC endpoint Allow statements must limit Resource to authorized buckets: %v", [authorized_buckets])
