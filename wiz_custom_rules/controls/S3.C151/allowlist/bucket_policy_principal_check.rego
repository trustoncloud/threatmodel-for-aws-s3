package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Parse Policy
policy_doc := doc {
    has_input
    is_string(input.policy)
    doc := json.unmarshal(input.policy)
} else := doc {
    has_input
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

# Helper: Get Authorized Principals from Parameters
# Example: ["arn:aws:iam::123456789012:role/MyBackUpRole", "arn:aws:iam::123456789012:root"]
authorized_principals := input.parameters.authorized_principals

# Helper: Extract Principals granted access (Allow statements)
# We focus on the "AWS" key in the Principal object, which denotes IAM entities.
granted_principals[principal] {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    
    # Check Principal.AWS block
    # Case 1: "Principal": { "AWS": "arn:..." }
    is_string(statement.Principal.AWS)
    principal := statement.Principal.AWS
}
granted_principals[principal] {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    
    # Case 2: "Principal": { "AWS": ["arn:...", "arn:..."] }
    is_array(statement.Principal.AWS)
    principal := statement.Principal.AWS[_]
}
granted_principals[principal] {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    
    # Case 3: "Principal": "*" or "Principal": { "AWS": "*" }
    # This acts as a wildcard principal.
    statement.Principal == "*"
    principal := "*"
}
granted_principals[principal] {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    
    is_string(statement.Principal.AWS)
    statement.Principal.AWS == "*"
    principal := "*"
}

# Helper: Check if a principal is authorized
is_authorized(principal) {
    authorized_principals[_] == principal
}

# Helper: Find Unauthorized Principals
unauthorized_principals[p] {
    p := granted_principals[_]
    not is_authorized(p)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if we find any allowed principal that is NOT in the authorized list
    count(unauthorized_principals) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket policy grants access to unauthorized principals: %v", [unauthorized_principals]) {
    result == "fail"
} else := "Bucket policy grants access only to authorized principals."

expectedConfiguration := "Bucket policy 'Principal' element must only contain ARNs listed in 'authorized_principals' for 'Allow' statements."