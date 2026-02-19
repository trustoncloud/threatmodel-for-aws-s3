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

# Helper: Get Authorized Key from Parameters
# Expects a single Key ARN string: "arn:aws:kms:us-east-1:123456789012:key/my-key"
authorized_key := input.parameters.authorized_kms_key_id

# Helper: Check if Action covers s3:PutObject
is_put_object_action(action) {
    action == "s3:PutObject"
}
is_put_object_action(action) {
    action == "s3:*"
}
is_put_object_action(action) {
    action == "*"
}
is_put_object_action(action) {
    is_array(action)
    val := action[_]
    val == "s3:PutObject"
}

# Helper: Verify the statement enforces the specific key
# Logic: "Effect: Deny" + "Action: PutObject" + "Condition: StringNotEquals(KeyHeader, AuthKey)"
# This translates to: "If the key is NOT the authorized one, Deny the request."
enforces_authorized_key {
    statement := policy_statements[_]
    
    # 1. Must be a Deny statement
    statement.Effect == "Deny"
    
    # 2. Must cover PutObject
    is_put_object_action(statement.Action)
    
    # 3. Must check the encryption key header
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    
    # 4. Check specific header key
    # Key: "s3:x-amz-server-side-encryption-aws-kms-key-id"
    val := conditions[key]
    lower(key) == "s3:x-amz-server-side-encryption-aws-kms-key-id"
    
    # 5. The value must be the authorized key
    val == authorized_key
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists (Implicitly allows any valid key)
    not policy_doc
} else := "fail" {
    # Fail if we cannot find the enforcement rule
    not enforces_authorized_key
}

# --- Metadata ---
currentConfiguration := "Bucket policy does not restrict PutObject requests to the authorized KMS Key." {
    result == "fail"
} else := "Bucket policy strictly enforces usage of the authorized KMS Key."

expectedConfiguration := "Bucket policy must Deny 's3:PutObject' if 's3:x-amz-server-side-encryption-aws-kms-key-id' does not match the 'authorized_kms_key_id'."