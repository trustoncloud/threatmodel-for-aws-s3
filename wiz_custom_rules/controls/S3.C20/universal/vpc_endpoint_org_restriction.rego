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

# Helper: Normalize Statements
policy_statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
} 
policy_statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

# Helper: Define valid Org restriction keys
is_org_key("aws:PrincipalOrgID")
is_org_key("aws:PrincipalOrgPaths")
is_org_key("aws:PrincipalAccount")

# Helper: Check if the policy restricts access based on Org identity
# We just need to find ONE Deny statement that uses an Org Condition Key.
# We don't care *what* the value is, just that the restriction exists.
has_org_restriction {
    # 1. Iterate over statements
    statement := policy_statements[_]
    statement.Effect == "Deny"
    
    # 2. Iterate over Condition operators
    # Look for StringNotEquals (standard for "Deny everyone NOT in my Org")
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    
    # 3. Iterate over Condition keys
    # Check if the condition key is one of the Org keys
    _ = conditions[key]
    is_org_key(key)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    not has_policy
} else := "fail" {
    # Fail if we cannot find any Org-based restriction logic
    not has_org_restriction
}

# --- Metadata ---
currentConfiguration := "VPC Endpoint Policy does not restrict access to specific Organizations or OUs." {
    result == "fail"
} else := "VPC Endpoint Policy restricts access to specific Organizations or OUs."

expectedConfiguration := "VPC Endpoint Policy must contain a 'Deny' statement using 'StringNotEquals' on 'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths', or 'aws:PrincipalAccount'."