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

# Helper: Get Authorized VPCs from Parameters
# Expects a list of VPC IDs: ["vpc-12345678", "vpc-87654321"]
authorized_vpcs := input.parameters.authorized_vpcs

# Helper: Extract the VPCs allowed by the policy
# Logic: If the policy says "Deny if SourceVpc is StringNotEquals X", it means X is ALLOWED.
# We collect all such "X" values.
allowed_by_policy[vpc_id] {
    statement := policy_statements[_]
    
    # 1. Must be a Deny statement (Strict isolation)
    statement.Effect == "Deny"
    
    # 2. Look for the Condition block
    conditions := statement.Condition[operator]
    
    # 3. Operator must be "StringNotEquals" (Deny everyone EXCEPT...)
    contains(lower(operator), "stringnotequals")
    
    # 4. Key must be aws:SourceVpc
    val := conditions[key]
    lower(key) == "aws:sourcevpc"
    
    # 5. Extract value (handle string or array)
    is_string(val)
    vpc_id := val
}
allowed_by_policy[vpc_id] {
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    
    values := conditions[key]
    lower(key) == "aws:sourcevpc"
    
    # Handle Array
    is_array(values)
    vpc_id := values[_]
}

# Helper: Check if a VPC ID is authorized
is_vpc_authorized(vpc) {
    # Check if 'vpc' is in the input parameters
    authorized_vpcs[_] == vpc
}

# Helper: Find any VPC permitted by the policy that is NOT in our authorized list
unauthorized_access_found {
    # Iterate over VPCs allowed by the policy
    vpc := allowed_by_policy[_]
    
    # Fail if this VPC is not in our authorized list
    not is_vpc_authorized(vpc)
}

# Helper: Check if there is any restriction at all
has_vpc_restriction {
    count(allowed_by_policy) > 0
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if no policy exists (Implicitly allows public/authenticated access depending on ACLs)
    not policy_doc
} else := "fail" {
    # Fail if there is no "Deny-Except-VPC" logic found
    not has_vpc_restriction
} else := "fail" {
    # Fail if the policy allows a VPC we didn't authorize
    unauthorized_access_found
}

# --- Metadata ---
currentConfiguration := "Bucket policy does not limit access to authorized VPCs." {
    result == "fail"
} else := "Bucket policy restricts access to authorized VPCs."

expectedConfiguration := "Bucket policy must contain a 'Deny' statement using 'StringNotEquals' on 'aws:SourceVpc' to block all traffic except from 'authorized_vpcs'."