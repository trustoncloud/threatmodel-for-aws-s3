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

# Helper: Get Authorized Roles from Parameters
# Example: ["arn:aws:iam::123:role/service-role/MyLogRole"]
authorized_roles := input.parameters.authorized_service_roles

# Helper: Extract the Roles exempted from the Deny (i.e., the "Allowed" ones)
# Logic: "Deny if PrincipalArn StringNotEquals X" -> X is Allowed.
allowed_by_policy[role_arn] {
    statement := policy_statements[_]
    
    # 1. Must be a Deny statement
    statement.Effect == "Deny"
    
    # 2. Iterate Conditions
    conditions := statement.Condition[operator]
    
    # 3. Operator must be "StringNotEquals" or "ArnNotEquals"
    contains(lower(operator), "notequals")
    
    # 4. Key must be aws:PrincipalArn
    val := conditions[key]
    lower(key) == "aws:principalarn"
    
    # 5. Extract value (handle string or array)
    is_string(val)
    role_arn := val
}
allowed_by_policy[role_arn] {
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    conditions := statement.Condition[operator]
    contains(lower(operator), "notequals")
    
    values := conditions[key]
    lower(key) == "aws:principalarn"
    
    # Handle Array
    is_array(values)
    role_arn := values[_]
}

# Helper: Check if a role is authorized
is_role_authorized(role) {
    authorized_roles[_] == role
}

# Helper: Find any Role permitted by the policy that is NOT in our authorized list
unauthorized_access_found {
    role := allowed_by_policy[_]
    not is_role_authorized(role)
}

# Helper: Check if there is any restriction at all
has_role_restriction {
    count(allowed_by_policy) > 0
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists
    not policy_doc
} else := "fail" {
    # Fail if there is no "Deny-Except-Role" logic found
    not has_role_restriction
} else := "fail" {
    # Fail if the policy allows a Role we didn't authorize
    unauthorized_access_found
}

# --- Metadata ---
currentConfiguration := "Bucket policy does not strictly block unauthorized service roles." {
    result == "fail"
} else := "Bucket policy strictly blocks unauthorized service roles."

expectedConfiguration := "Bucket policy must contain a 'Deny' statement using 'StringNotEquals' on 'aws:PrincipalArn' to block all principals except those in 'authorized_service_roles'."