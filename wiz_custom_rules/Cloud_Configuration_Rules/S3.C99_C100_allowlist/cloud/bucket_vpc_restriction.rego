package wiz

# --- Configuration ---
authorized_vpcs := {
    "vpc-0123456789abcdef0",
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

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

# A Deny for everyone on all S3 actions whose only condition is a
# StringNotEquals on aws:SourceVpc allows exactly the listed VPCs.
vpc_condition_values(stmt) := vals {
    stmt.Effect == "Deny"
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    restriction_operators[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "aws:sourcevpc"
    vals := as_array(val)
}

restricted_scope[arn] {
    stmt := statements[_]
    vpc_condition_values(stmt)
    arn := scope_arns[_]
    resource_covers(stmt, arn)
}

allowed_by_policy[vpc] {
    vpc := vpc_condition_values(statements[_])[_]
}

has_vpc_restriction {
    count(restricted_scope) == count(scope_arns)
}

unauthorized_vpcs := allowed_by_policy - authorized_vpcs

result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_vpc_restriction
} else := "fail" {
    count(unauthorized_vpcs) > 0
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so access is not limited to authorized VPCs." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy allows unauthorized VPC(s): %v", [unauthorized_vpcs]) {
    result == "fail"
    count(unauthorized_vpcs) > 0
} else := "Bucket policy has no VPC restriction that applies to all principals and all S3 actions on the bucket and its objects, with no other condition." {
    result == "fail"
} else := "Bucket policy restricts access to authorized VPCs."

expectedConfiguration := sprintf("Bucket policy must contain a Deny for all principals and all S3 actions on the bucket and its objects whose only condition is StringNotEquals on aws:SourceVpc, listing only authorized VPCs: %v", [authorized_vpcs])
