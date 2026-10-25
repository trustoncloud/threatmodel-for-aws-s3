package wiz

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

# The policy restricts by organization when any Deny + StringNotEquals uses an
# org condition key. This mode does not check the specific values.
has_org_restriction {
    statement := statements[_]
    statement.Effect == "Deny"
    conditions := statement.Condition[operator]
    contains(lower(operator), "stringnotequals")
    val := conditions[key]
    is_org_key(lower(key))
    val != null
}

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    not has_org_restriction
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so access is not restricted by organization." {
    result == "fail"
    input.PolicyDocument == null
} else := "VPC endpoint policy does not restrict access by organization." {
    result == "fail"
} else := "VPC endpoint policy restricts access by organization."

expectedConfiguration := "S3 VPC endpoint policy must contain a Deny with StringNotEquals on aws:PrincipalOrgID, aws:PrincipalOrgPaths, or aws:PrincipalAccount."
