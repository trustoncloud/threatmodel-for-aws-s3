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

# Helper: Get Target Buckets (The Allowlist)
# These are the buckets that MUST enforce SSE-C.
target_buckets := input.parameters.target_ssec_buckets

# Helper: Check if this bucket is targeted
# We check if the bucket Name matches any in the list
is_target_bucket {
    target_buckets[_] == input.name
}

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

# Helper: Verify the statement Enforces SSE-C
# We look for a Deny statement that activates if the SSE-C algorithm is NOT "AES256".
enforces_ssec {
    statement := policy_statements[_]
    
    # 1. Must be a Deny statement
    statement.Effect == "Deny"
    
    # 2. Must cover PutObject
    is_put_object_action(statement.Action)
    
    # 3. Check Condition for SSE-C Header
    conditions := statement.Condition[operator]
    
    # We accept either StringNotEquals: "AES256" OR Null: "true" (missing header)
    # Valid Condition 1: StringNotEquals
    contains(lower(operator), "stringnotequals")
    val := conditions[key]
    lower(key) == "s3:x-amz-server-side-encryption-customer-algorithm"
    val == "AES256"
}
enforces_ssec {
    statement := policy_statements[_]
    statement.Effect == "Deny"
    is_put_object_action(statement.Action)
    
    # Valid Condition 2: Null check (Header is missing)
    conditions := statement.Condition[operator]
    contains(lower(operator), "null")
    val := conditions[key]
    lower(key) == "s3:x-amz-server-side-encryption-customer-algorithm"
    val == "true"
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "pass" {
    # If this bucket is NOT in the target list, we skip the check (Pass).
    # This prevents false positives on normal buckets.
    not is_target_bucket
} else := "fail" {
    # Fail if it IS a target bucket but has no policy
    is_target_bucket
    not policy_doc
} else := "fail" {
    # Fail if it IS a target bucket but policy does not enforce SSE-C
    is_target_bucket
    not enforces_ssec
}

# --- Metadata ---
currentConfiguration := "Target bucket does not enforce SSE-C (Customer-Provided Keys)." {
    result == "fail"
} else := "Bucket enforces SSE-C (or is not required to)."

expectedConfiguration := "Buckets listed in 'target_ssec_buckets' must have a Bucket Policy Denying 's3:PutObject' if 's3:x-amz-server-side-encryption-customer-algorithm' is missing or not 'AES256'."