package wiz

# --- Logic ---
default result := "pass"

# The bucket policy arrives as a JSON string at input.bucketPolicy.
policy_doc := doc {
    is_string(input.bucketPolicy)
    doc := json.unmarshal(input.bucketPolicy)
} else := doc {
    is_object(input.bucketPolicy)
    doc := input.bucketPolicy
}

# Only judge when Wiz successfully fetched the bucket policy; null with a
# fetch error means unreadable, not absent.
fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketPolicy.result == "Success"
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

# The deny must cover all S3 actions to block traffic comprehensively.
covers_all_s3(action) { action == "s3:*" }
covers_all_s3(action) { action == "*" }
covers_all_s3(action) { action[_] == "s3:*" }
covers_all_s3(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

# The deny must apply to every principal.
applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The deny must reach the bucket itself and every object in it; the sample
# object ARN stands in for any key.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

scope_arns := {bucket_arn, sprintf("%s/sample-object", [bucket_arn])}

as_array(v) := v { is_array(v) } else := [v]

resource_covers(stmt, arn) {
    glob.match(as_array(stmt.Resource)[_], [], arn)
}

secure_transport_false(v) { v == "false" }
secure_transport_false(v) { v == false }
secure_transport_false(v) { v[_] == "false" }

tls_floor_ok(v) { to_number(v) >= 1.2 }
tls_floor_ok(v) { to_number(v[_]) >= 1.2 }

# The transport test must be the only condition; any extra key narrows the deny.
sole_condition(stmt, operator) {
    count(stmt.Condition) == 1
    count(stmt.Condition[operator]) == 1
}

scoped_deny(stmt) {
    stmt.Effect == "Deny"
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
}

denies_insecure_transport(stmt) {
    scoped_deny(stmt)
    sole_condition(stmt, "Bool")
    secure_transport_false(stmt.Condition.Bool["aws:SecureTransport"])
}

denies_unauthorized_tls(stmt) {
    scoped_deny(stmt)
    sole_condition(stmt, "NumericLessThan")
    tls_floor_ok(stmt.Condition.NumericLessThan["s3:TlsVersion"])
}

# Qualifying denies may split the bucket and object ARNs across statements.
transport_scope[arn] {
    stmt := statements[_]
    denies_insecure_transport(stmt)
    arn := scope_arns[_]
    resource_covers(stmt, arn)
}

tls_scope[arn] {
    stmt := statements[_]
    denies_unauthorized_tls(stmt)
    arn := scope_arns[_]
    resource_covers(stmt, arn)
}

has_secure_transport_deny {
    count(transport_scope) == count(scope_arns)
}

has_tls_floor_deny {
    count(tls_scope) == count(scope_arns)
}

# Both protections are required; missing either one is non-compliant.
result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_secure_transport_deny
} else := "fail" {
    not has_tls_floor_deny
}

# --- Metadata ---
missing_protections[p] {
    not has_secure_transport_deny
    p := "a Deny of unencrypted requests (aws:SecureTransport false)"
}

missing_protections[p] {
    not has_tls_floor_deny
    p := "a Deny of TLS versions below 1.2 (s3:TlsVersion)"
}

currentConfiguration := "Bucket has no bucket policy, so nothing blocks unencrypted requests or old TLS versions." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy lacks %s. Each Deny must apply to all principals and all S3 actions on the bucket and its objects, with no other condition.", [concat(" and ", [p | p := missing_protections[_]])]) {
    result == "fail"
} else := "Bucket policy denies unencrypted requests and TLS versions below 1.2 for all principals on the bucket and its objects."

expectedConfiguration := "Bucket policy must contain a Deny statement for all principals and all S3 actions on the bucket and its objects when aws:SecureTransport is false, and another when s3:TlsVersion is below 1.2. Each must carry no other condition."
