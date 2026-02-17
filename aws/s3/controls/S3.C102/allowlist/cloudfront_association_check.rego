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

# Helper: Get Authorized IDs (Distributions or OAIs)
# Example: ["E1234567890AB", "E378..."]
authorized_ids := input.parameters.authorized_cloudfront_ids

# --- Detection Logic ---

# 1. Identify statements relevant to CloudFront
is_cloudfront_statement(statement) {
    # Check Principal (Legacy OAI)
    # Format: "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123..."
    is_string(statement.Principal.AWS)
    contains(lower(statement.Principal.AWS), "cloudfront")
}
is_cloudfront_statement(statement) {
    # Check Principal (Legacy OAI - Array format)
    is_array(statement.Principal.AWS)
    principal := statement.Principal.AWS[_]
    contains(lower(principal), "cloudfront")
}
is_cloudfront_statement(statement) {
    # Check Service Principal (Modern OAC)
    # Format: "cloudfront.amazonaws.com"
    is_string(statement.Principal.Service)
    statement.Principal.Service == "cloudfront.amazonaws.com"
}
is_cloudfront_statement(statement) {
    # Check Service Principal (Array)
    is_array(statement.Principal.Service)
    service := statement.Principal.Service[_]
    service == "cloudfront.amazonaws.com"
}

# 2. Check if the statement matches an authorized ID
# We check both OAI (Principal) and OAC (Condition SourceArn) patterns.

is_authorized_statement(statement) {
    # Pattern A: OAI in Principal
    # We look for the Authorized ID inside the Principal string
    # e.g. "arn:aws:...Identity E123" contains "E123"
    auth_id := authorized_ids[_]
    
    # Handle String Principal
    is_string(statement.Principal.AWS)
    contains(statement.Principal.AWS, auth_id)
}
is_authorized_statement(statement) {
    # Pattern A: OAI in Principal (Array)
    auth_id := authorized_ids[_]
    is_array(statement.Principal.AWS)
    p := statement.Principal.AWS[_]
    contains(p, auth_id)
}

is_authorized_statement(statement) {
    # Pattern B: OAC (Origin Access Control)
    # Checks Condition "AWS:SourceArn" for the Distribution ID
    # e.g. "arn:aws:cloudfront::123:distribution/E123..." contains "E123..."
    
    # Extract Condition Block
    conditions := statement.Condition[operator]
    
    # Check for SourceArn key
    val := conditions[key]
    lower(key) == "aws:sourcearn"
    
    # Check if the Authorized ID is in the Source ARN
    auth_id := authorized_ids[_]
    
    # Handle String value
    is_string(val)
    contains(val, auth_id)
}
is_authorized_statement(statement) {
    # Pattern B: OAC (Array value in condition)
    conditions := statement.Condition[operator]
    vals := conditions[key]
    lower(key) == "aws:sourcearn"
    
    is_array(vals)
    val := vals[_]
    
    auth_id := authorized_ids[_]
    contains(val, auth_id)
}

# 3. Find Unauthorized Allow Statements
# We are looking for:
# - Effect: Allow
# - It IS a CloudFront statement
# - It is NOT authorized
has_unauthorized_association {
    statement := policy_statements[_]
    statement.Effect == "Allow"
    is_cloudfront_statement(statement)
    not is_authorized_statement(statement)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists (Implicitly okay, but if we are checking for "Unauthorized ASSOCIATION", 
    # a missing policy means no association exists, which is technically a PASS for this specific check.
    # However, usually we default to Pass if no policy exists.)
    # If parameters are provided, we assume the user wants to enforce something.
    # But if there is no policy, there is no CloudFront access, so it is secure regarding this control.
    false 
} else := "fail" {
    has_unauthorized_association
}

# --- Metadata ---
currentConfiguration := "Bucket allows CloudFront access to unauthorized distributions/identities." {
    result == "fail"
} else := "Bucket restricts CloudFront access to authorized distributions/identities."

expectedConfiguration := "Bucket Policy granting CloudFront access must target only IDs listed in 'authorized_cloudfront_ids' via Principal (OAI) or Condition SourceArn (OAC)."