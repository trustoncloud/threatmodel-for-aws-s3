package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Check if policy exists
has_policy {
    has_input
    input.policy != null
}

# Helper: Parse the policy
policy_doc := doc {
    has_policy
    is_string(input.policy)
    doc := json.unmarshal(input.policy)
} else := doc {
    has_policy
    is_object(input.policy)
    doc := input.policy
}

# Helper: Normalize Statements
policy_statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
} 
policy_statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

# Helper: Get Authorized Buckets from parameters
# Expects a list of ARNs: ["arn:aws:s3:::my-corp-data", "arn:aws:s3:::my-logs"]
authorized_buckets := input.parameters.authorized_buckets

# Helper: Check if a resource string matches an authorized bucket
is_authorized_resource(res) {
    # Check exact match against authorized list
    authorized_buckets[_] == res
}
is_authorized_resource(res) {
    # Check if resource is a sub-resource of an authorized bucket (e.g. bucket/*)
    # We strip the "/*" suffix to compare the base bucket ARN
    endswith(res, "/*")
    base_arn := substring(res, 0, count(res) - 2)
    authorized_buckets[_] == base_arn
}

# Helper: Find Unauthorized Resources in Allow statements
# We are looking for any "Allow" rule that grants access to something NOT in our list.
unauthorized_allowances[res] {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    
    # Normalize Resource to a list/set for iteration
    # Handle String case
    is_string(statement.Resource)
    res := statement.Resource
    not is_authorized_resource(res)
}
unauthorized_allowances[res] {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    
    # Handle Array case
    is_array(statement.Resource)
    res := statement.Resource[_]
    not is_authorized_resource(res)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists (Default is Allow *, which is insecure)
    not has_policy
} else := "fail" {
    # Fail if we find any allowed resource that isn't authorized
    # This catches "Resource": "*" as well, since "*" is not in the authorized list.
    count(unauthorized_allowances) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("VPC Endpoint allows access to unauthorized buckets: %v", [unauthorized_allowances]) {
    result == "fail"
} else := "VPC Endpoint is restricted to authorized S3 buckets."

expectedConfiguration := "VPC Endpoint Policy must limit 'Resource' in 'Allow' statements to only the ARNs listed in 'authorized_buckets'."