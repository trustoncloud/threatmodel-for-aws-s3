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

# Helper: Get Authorized Access Points from Parameters
# Expects a list of ARNs: ["arn:aws:s3:us-east-1:123:accesspoint/finance-ap"]
authorized_aps := input.parameters.authorized_access_points

# Helper: Extract the Access Points allowed by the policy
# Logic: If the policy says "Deny if s3:DataAccessPointArn StringNotEquals X", it means X is ALLOWED.
# We collect all such "X" values found in valid Deny statements.
allowed_by_policy[ap_arn] {
    statement := policy_statements[_]
    
    # 1. Must be a Deny statement
    statement.Effect == "Deny"
    
    # 2. Iterate Conditions
    conditions := statement.Condition[operator]
    
    # 3. Operator must be "StringNotEquals" (Deny everyone EXCEPT...)
    contains(lower(operator), "stringnotequals")
    
    # 4. Key must be s3:DataAccessPointArn
    val := conditions[key]
    lower(key) == "s3:dataaccesspointarn"
    
    # 5. Extract value (handle string or array)
    is_string(val)
    ap_arn := val
}
allowed_by_policy[ap_arn] {
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    
    values := conditions[key]
    lower(key) == "s3:dataaccesspointarn"
    
    # Handle Array
    is_array(values)
    ap_arn := values[_]
}

# Helper: Check if an Access Point ARN is authorized
is_ap_authorized(ap) {
    # Iterate over authorized list
    authorized_aps[_] == ap
}

# Helper: Find any AP permitted by the policy that is NOT in our authorized list
unauthorized_access_found {
    # Iterate over APs allowed by the policy
    ap := allowed_by_policy[_]
    
    # Fail if this AP is not in our authorized list
    not is_ap_authorized(ap)
}

# Helper: Check if there is any restriction at all
has_ap_restriction {
    count(allowed_by_policy) > 0
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists
    not policy_doc
} else := "fail" {
    # Fail if there is no "Deny-Except-AP" logic found
    not has_ap_restriction
} else := "fail" {
    # Fail if the policy allows an AP we didn't authorize
    unauthorized_access_found
}

# --- Metadata ---
currentConfiguration := "Bucket policy does not restrict access to authorized Access Points." {
    result == "fail"
} else := "Bucket policy restricts access to authorized Access Points."

expectedConfiguration := "Bucket policy must contain a 'Deny' statement using 'StringNotEquals' on 's3:DataAccessPointArn' to block all traffic except from 'authorized_access_points'."