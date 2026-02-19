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

# Helper: Identify Actions that change ACLs (Without 'in' keyword)
# 1. Exact String Match
is_acl_action(action) {
    action == "s3:PutObjectAcl"
}
is_acl_action(action) {
    action == "s3:*"
}
is_acl_action(action) {
    action == "*"
}
# 2. Array Match
is_acl_action(action) {
    is_array(action)
    val := action[_]
    val == "s3:PutObjectAcl"
}
is_acl_action(action) {
    is_array(action)
    val := action[_]
    val == "s3:*"
}
is_acl_action(action) {
    is_array(action)
    val := action[_]
    val == "*"
}

# Helper: Identify Public ACL flags (Without 'in' keyword)
# The header 'x-amz-acl' controls the canned ACL. 
# Dangerous values: 'public-read', 'public-read-write'.
is_public_acl_condition(statement) {
    # Iterate over conditions (Implicit loop)
    conditions := statement.Condition[operator]
    
    # Check for StringEquals or StringLike
    # We look for the specific header key
    val := conditions[key]
    lower(key) == "s3:x-amz-acl"
    
    # Verify the value is dangerous
    has_public_value(val)
}

has_public_value(val) {
    val == "public-read"
}
has_public_value(val) {
    val == "public-read-write"
}
has_public_value(val) {
    is_array(val)
    v := val[_]
    v == "public-read"
}
has_public_value(val) {
    is_array(val)
    v := val[_]
    v == "public-read-write"
}

# Helper: Check for the Block
has_public_acl_block {
    statement := policy_statements[_]
    
    # 1. Effect must be Deny
    statement.Effect == "Deny"
    
    # 2. Action must cover PutObjectAcl
    is_acl_action(statement.Action)
    
    # 3. Condition must target public ACLs
    is_public_acl_condition(statement)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists (Default VPC Endpoint policy allows everything)
    not policy_doc
} else := "fail" {
    # Fail if the specific blocking rule is missing
    not has_public_acl_block
}

# --- Metadata ---
currentConfiguration := "VPC Endpoint Policy allows setting Object ACLs to public." {
    result == "fail"
} else := "VPC Endpoint Policy explicitly blocks setting Object ACLs to public."

expectedConfiguration := "VPC Endpoint Policy must Deny 's3:PutObjectAcl' when 's3:x-amz-acl' is 'public-read' or 'public-read-write'."