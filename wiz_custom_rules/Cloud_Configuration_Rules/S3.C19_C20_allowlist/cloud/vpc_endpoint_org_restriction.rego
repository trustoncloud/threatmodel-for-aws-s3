package wiz

# --- Configuration ---
# Authorized org IDs, org paths, or account IDs allowed through the endpoint.
authorized_orgs := {
    "o-exampleorgid",
}

# --- Logic ---
default result := "pass"

is_s3_endpoint {
    endswith(input.ServiceName, ".s3")
}

policy_doc := doc {
    is_string(input.PolicyDocument)
    doc := json.unmarshal(input.PolicyDocument)
} else := doc {
    is_object(input.PolicyDocument)
    doc := input.PolicyDocument
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

is_org_key("aws:principalorgid")
is_org_key("aws:principalorgpaths")
is_org_key("aws:principalaccount")

# A Deny + StringNotEquals on an org key allows exactly the listed values.
org_condition_values(statement) := val {
    statement.Effect == "Deny"
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    val := conditions[key]
    is_org_key(lower(key))
}

enforced_orgs[org] {
    v := org_condition_values(statements[_])
    is_string(v)
    org := v
}

enforced_orgs[org] {
    v := org_condition_values(statements[_])
    org := v[_]
}

has_enforcement {
    count(enforced_orgs) > 0
}

unauthorized_orgs := enforced_orgs - authorized_orgs

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    not has_enforcement
} else := "fail" {
    count(unauthorized_orgs) > 0
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so access is not restricted to authorized organizations." {
    result == "fail"
    input.PolicyDocument == null
} else := sprintf("VPC endpoint allows unauthorized organization(s)/account(s): %v", [unauthorized_orgs]) {
    result == "fail"
    count(unauthorized_orgs) > 0
} else := "VPC endpoint policy does not restrict access to authorized organizations." {
    result == "fail"
} else := "VPC endpoint restricts access to authorized organizations."

expectedConfiguration := sprintf("S3 VPC endpoint policy must Deny with StringNotEquals on aws:PrincipalOrgID/OrgPaths/Account listing only authorized values: %v", [authorized_orgs])
