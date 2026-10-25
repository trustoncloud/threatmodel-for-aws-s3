package wiz

# --- Logic ---
default result := "pass"

# Only S3 VPC endpoints are in scope; the vpcEndpoint native type covers every
# service, so filter by service name.
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

covers_all_actions(action) { action == "*" }
covers_all_actions(action) { action == "s3:*" }
covers_all_actions(action) { action[_] == "*" }
covers_all_actions(action) { action[_] == "s3:*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

# The deny must apply to every principal.
applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The endpoint reaches every bucket, so the deny must cover any bucket and any
# object; the sample ARNs stand in for them in each partition.
partitions := {"aws", "aws-cn", "aws-us-gov"}

scope_suffixes := {"sample-bucket", "sample-bucket/sample-object"}

as_array(v) := v { is_array(v) } else := [v]

resource_covers(stmt, suffix) {
    glob.match(as_array(stmt.Resource)[_], [], sprintf("arn:%s:s3:::%s", [partitions[_], suffix]))
}

value_false(v) { v == "false" }
value_false(v) { v == false }
value_false(v) { v[_] == "false" }

tls_floor_ok(v) { to_number(v) >= 1.2 }
tls_floor_ok(v) { to_number(v[_]) >= 1.2 }

# The transport test must be the only condition; any extra key narrows the deny.
sole_condition(stmt, operator) {
    count(stmt.Condition) == 1
    count(stmt.Condition[operator]) == 1
}

scoped_deny(stmt) {
    stmt.Effect == "Deny"
    covers_all_actions(stmt.Action)
    applies_to_everyone(stmt.Principal)
}

denies_insecure_transport(stmt) {
    sole_condition(stmt, "Bool")
    value_false(stmt.Condition.Bool["aws:SecureTransport"])
}

denies_old_tls(stmt) {
    sole_condition(stmt, "NumericLessThan")
    tls_floor_ok(stmt.Condition.NumericLessThan["s3:TlsVersion"])
}

# Qualifying denies of one kind may split bucket and object coverage.
transport_scope[suffix] {
    stmt := statements[_]
    scoped_deny(stmt)
    denies_insecure_transport(stmt)
    suffix := scope_suffixes[_]
    resource_covers(stmt, suffix)
}

tls_scope[suffix] {
    stmt := statements[_]
    scoped_deny(stmt)
    denies_old_tls(stmt)
    suffix := scope_suffixes[_]
    resource_covers(stmt, suffix)
}

# Either protection satisfies the control.
has_secure_transport_deny {
    count(transport_scope) == count(scope_suffixes)
}

has_secure_transport_deny {
    count(tls_scope) == count(scope_suffixes)
}

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    not has_secure_transport_deny
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so it does not deny insecure transport." {
    result == "fail"
    input.PolicyDocument == null
} else := "VPC endpoint policy has no Deny of insecure transport that applies to all principals, all S3 actions and all buckets and objects, with no other condition." {
    result == "fail"
} else := "VPC endpoint policy denies insecure transport for all principals, buckets and objects."

expectedConfiguration := "S3 VPC endpoint policy must contain a Deny for all principals and all S3 actions on all buckets and objects when aws:SecureTransport is false or s3:TlsVersion is below 1.2, with no other condition."
