package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Check if this is an SCP (Service Control Policy)
is_scp {
    input.type == "SERVICE_CONTROL_POLICY"
}

# Helper: Parse Policy Content
policy_doc := doc {
    has_input
    is_scp
    is_string(input.content)
    doc := json.unmarshal(input.content)
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

# Helper: Check if Action covers S3 (s3:* or *)
# 1. Case: Action is a simple string
is_comprehensive_action(action) {
    action == "s3:*"
}
is_comprehensive_action(action) {
    action == "*"
}
# 2. Case: Action is an array (Check if "s3:*" is inside)
is_comprehensive_action(action) {
    is_array(action)
    some i
    action[i] == "s3:*"
}
# 3. Case: Action is an array (Check if "*" is inside)
is_comprehensive_action(action) {
    is_array(action)
    some i
    action[i] == "*"
}

# Helper: Check for aws:SecureTransport = false
has_secure_transport_bool(statement) {
    statement.Condition.Bool["aws:SecureTransport"] == "false"
}
has_secure_transport_bool(statement) {
    statement.Condition.Bool["aws:SecureTransport"] == false
}

# Helper: Check for s3:TlsVersion < 1.2
has_tls_version_enforcement(statement) {
    val := statement.Condition.NumericLessThan["s3:TlsVersion"]
    to_number(val) == 1.2
}

# Helper: Group valid conditions
valid_condition(statement) {
    has_secure_transport_bool(statement)
}
valid_condition(statement) {
    has_tls_version_enforcement(statement)
}

# Helper: Verify if a compliant Deny statement exists
has_compliant_scp_statement {
    some statement
    policy_statements[statement]
    
    # 1. Effect
    statement.Effect == "Deny"
    
    # 2. Action (Must block S3)
    is_comprehensive_action(statement.Action)
    
    # 3. Conditions (SecureTransport OR TLS Version)
    valid_condition(statement)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "skip" {
    # Skip if this isn't an SCP
    not is_scp
} else := "fail" {
    # Fail if the SCP does not have the mandatory security block
    not has_compliant_scp_statement
}

# --- Metadata ---
currentConfiguration := "SCP does not enforce SecureTransport or TLS 1.2 for S3." {
    result == "fail"
} else := "SCP strictly enforces SecureTransport or TLS 1.2 for S3."

expectedConfiguration := "Service Control Policy (SCP) must contain a 'Deny' statement for 's3:*' when 'aws:SecureTransport' is false or 's3:TlsVersion' < 1.2."