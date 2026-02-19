package wiz

# --- Logic ---
default result := "pass"

# Helper: Check if input exists
has_input {
    input != null
}

# Helper: Check if policy exists
has_policy {
    has_input
    input.policy != null
}

# Helper: Parse the policy for analysis
# Handles both stringified JSON (standard) and pre-parsed Objects
policy_doc := doc {
    has_policy
    is_string(input.policy)
    doc := json.unmarshal(input.policy)
} else := doc {
    has_policy
    is_object(input.policy)
    doc := input.policy
}

# Helper: Normalize Statement to a set/array
# AWS allows "Statement" to be a Dict (one statement) or List (multiple).
policy_statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
} 
policy_statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

# Helper: Check if Action covers all operations (* or s3:*)
is_comprehensive_action(action) {
    action == "*"
}
is_comprehensive_action(action) {
    action == "s3:*"
}
is_comprehensive_action(action) {
    is_array(action)
    some i
    action[i] == "*"
}
is_comprehensive_action(action) {
    is_array(action)
    some i
    action[i] == "s3:*"
}

# Helper: Check for aws:SecureTransport = false
has_secure_transport_bool(statement) {
    # Handle string "false"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
}
has_secure_transport_bool(statement) {
    # Handle boolean false
    statement.Condition.Bool["aws:SecureTransport"] == false
}

# Helper: Check for s3:TlsVersion < 1.2
has_tls_version_enforcement(statement) {
    val := statement.Condition.NumericLessThan["s3:TlsVersion"]
    to_number(val) == 1.2
}

# Helper: Check if the condition block is valid (either Bool or TLS version)
valid_condition(statement) {
    has_secure_transport_bool(statement)
}
valid_condition(statement) {
    has_tls_version_enforcement(statement)
}

# Helper: Verify if a compliant Deny statement exists
has_compliant_statement {
    some statement
    policy_statements[statement]
    
    # 1. Check Effect
    statement.Effect == "Deny"
    
    # 2. Check Action (Must cover all requests)
    is_comprehensive_action(statement.Action)
    
    # 3. Check Conditions (Either SecureTransport or TLS Version)
    valid_condition(statement)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists (VPC Endpoints default to Full Access if no policy, which is insecure)
    not has_policy
} else := "fail" {
    # Fail if policy exists but lacks the specific enforcement
    not has_compliant_statement
}

# --- Metadata ---
currentConfiguration := "VPC Endpoint Policy does not strictly deny insecure transport." {
    result == "fail"
} else := "VPC Endpoint Policy explicitly denies insecure transport."

expectedConfiguration := "VPC Endpoint Policy must contain a 'Deny' statement for all actions ('*') when 'aws:SecureTransport' is false or 's3:TlsVersion' < 1.2."