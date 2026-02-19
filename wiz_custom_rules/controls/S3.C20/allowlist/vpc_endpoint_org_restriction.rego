package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Check if policy exists
has_policy {
    has_input
    input.policy != null
}

# Helper: Parse the policy
policy_doc := doc {
    has_policy
    is_string(input.policy)
    doc := json.unmarshal(input.policy)
} else := doc {
    has_policy
    is_object(input.policy)
    doc := input.policy
}

# Helper: Normalize Statements to a Set
policy_statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
} 
policy_statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

# Helper: Retrieve authorized values from parameters
authorized_orgs := input.parameters.authorized_orgs

# Helper: Define valid Org restriction keys
is_org_key("aws:PrincipalOrgID")
is_org_key("aws:PrincipalOrgPaths")
is_org_key("aws:PrincipalAccount")

# Helper: Extract the values used in the "StringNotEquals" condition
# Returns the set of Org IDs/Paths that the policy is *allowing* (by denying everything else)
enforced_orgs[val] {
    # 1. Iterate over statements
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    # 2. Iterate over Condition operators (e.g., "StringNotEquals")
    # Using 'operator' as an unbound variable here triggers iteration over keys
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    
    # 3. Iterate over Condition keys (e.g., "aws:PrincipalOrgID")
    value := conditions[key]
    is_org_key(key)
    
    # 4. Handle Single String Value
    is_string(value)
    val := value
}

enforced_orgs[val] {
    # 1. Iterate over statements
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    # 2. Iterate over Condition operators
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    
    # 3. Iterate over Condition keys
    values := conditions[key]
    is_org_key(key)
    
    # 4. Handle Array of Values
    is_array(values)
    val := values[_]
}

# Helper: Check if an enforced value matches an authorized value
is_value_authorized(val) {
    # Check if 'val' exists inside the authorized_orgs array
    authorized_orgs[_] == val
}

# Helper: Check for any enforcement that is NOT authorized
has_unauthorized_enforcement {
    enforced_orgs[val]
    not is_value_authorized(val)
}

# Helper: Check if there is at least one valid enforcement
has_any_enforcement {
    count(enforced_orgs) > 0
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    not has_policy
} else := "fail" {
    # Fail if the policy has no Org/Account restrictions at all
    not has_any_enforcement
} else := "fail" {
    # Fail if the policy restricts to something, but that 'something' is not in our authorized list
    has_unauthorized_enforcement
}

# --- Metadata ---
currentConfiguration := "VPC Endpoint allows access to Organizations/OUs not in the authorized list." {
    result == "fail"
} else := "VPC Endpoint is restricted to authorized Organizations/OUs."

expectedConfiguration := "VPC Endpoint Policy must restrict access ('StringNotEquals') only to Organizations defined in the 'authorized_orgs' parameter."