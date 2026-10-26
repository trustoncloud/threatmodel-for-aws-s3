package wiz

# --- Configuration ---
authorized_service_roles := {
    "arn:aws:iam::123456789012:role/service-role/authorized-service-role",
}

# --- Logic ---
default result := "pass"

policy_doc := doc {
    is_string(input.bucketPolicy)
    doc := json.unmarshal(input.bucketPolicy)
} else := doc {
    is_object(input.bucketPolicy)
    doc := input.bucketPolicy
}

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

covers_all_s3(action) { action == "s3:*" }
covers_all_s3(action) { action == "*" }
covers_all_s3(action) { action[_] == "s3:*" }
covers_all_s3(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

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

restriction_operators := {"stringnotequals", "stringnotequalsifexists", "arnnotequals", "arnnotequalsifexists"}

# A Deny for everyone on all S3 actions whose only condition is a
# StringNotEquals or ArnNotEquals on aws:PrincipalArn exempts exactly the
# listed roles.
role_condition_values(stmt) := vals {
    stmt.Effect == "Deny"
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    restriction_operators[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "aws:principalarn"
    vals := as_array(val)
}

restricted_scope[arn] {
    stmt := statements[_]
    role_condition_values(stmt)
    arn := scope_arns[_]
    resource_covers(stmt, arn)
}

allowed_by_policy[role] {
    role := role_condition_values(statements[_])[_]
}

has_role_restriction {
    count(restricted_scope) == count(scope_arns)
}

unauthorized_roles := allowed_by_policy - authorized_service_roles

result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_role_restriction
} else := "fail" {
    count(unauthorized_roles) > 0
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so unauthorized service roles are not blocked." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy exempts unauthorized role(s) from the deny: %v", [unauthorized_roles]) {
    result == "fail"
    count(unauthorized_roles) > 0
} else := "Bucket policy has no block of unauthorized roles that applies to all principals and all S3 actions on the bucket and its objects, with no other condition." {
    result == "fail"
} else := "Bucket policy blocks all requests except from authorized service roles."

expectedConfiguration := sprintf("Bucket policy must contain a Deny for all principals and all S3 actions on the bucket and its objects whose only condition is StringNotEquals or ArnNotEquals on aws:PrincipalArn, exempting only authorized roles: %v", [authorized_service_roles])
