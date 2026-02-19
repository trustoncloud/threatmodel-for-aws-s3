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

# Helper: Get Buckets that REQUIRE SSE-C (The Exception List)
buckets_requiring_ssec := input.parameters.buckets_requiring_ssec

# Helper: Check if current bucket is in the "Requires SSE-C" list
is_ssec_required {
    buckets_requiring_ssec[_] == input.name
}

# Helper: Check if a statement BLOCKS SSE-C
# We look for a Deny statement on PutObject that triggers if SSE-C is used.
# Typically, this is done by Denying if "s3:x-amz-server-side-encryption-customer-algorithm" is NOT Null (i.e., it IS present).
blocks_ssec {
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    # Check Action covers PutObject
    is_put_action(statement.Action)
    
    # Check Condition: Deny if SSE-C header is present
    # Condition: "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "false" }
    # This means "If the header is NOT null (it exists), then Deny."
    conditions := statement.Condition[operator]
    contains(lower(operator), "null")
    
    val := conditions[key]
    lower(key) == "s3:x-amz-server-side-encryption-customer-algorithm"
    lower(val) == "false"
}

# Helper Action Check
is_put_action(action) {
    action == "s3:PutObject"
}
is_put_action(action) {
    action == "s3:*"
}
is_put_action(action) {
    action == "*"
}
is_put_action(action) {
    is_array(action)
    v := action[_]
    v == "s3:PutObject"
}

# --- Validation Logic ---

# Scenario 1: Bucket REQUIRES SSE-C
# Failure: If policy actively BLOCKS it.
fail_required_but_blocked {
    is_ssec_required
    blocks_ssec
}

# Scenario 2: Bucket DOES NOT require SSE-C (Standard Bucket)
# Failure: If policy DOES NOT block it (i.e., it allows it by default/omission).
fail_not_required_but_allowed {
    not is_ssec_required
    not blocks_ssec
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    fail_required_but_blocked
} else := "fail" {
    fail_not_required_but_allowed
}

# --- Metadata ---
currentConfiguration := "Bucket policy incorrectly handles SSE-C blocking based on requirements." {
    result == "fail"
} else := "Bucket policy correctly handles SSE-C usage permissions."

expectedConfiguration := "Buckets requiring SSE-C must NOT block it. All other buckets MUST block SSE-C usage (Deny if SSE-C header is not null)."