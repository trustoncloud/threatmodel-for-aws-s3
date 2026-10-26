package wiz

# --- Configuration ---
authorized_access_points := {
    "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap",
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

# The deny must reach every object in the bucket; the sample object ARN stands
# in for any key. Covering the bucket ARN as well is accepted but not required,
# since bucket settings calls cannot go through an access point.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

scope_arns := {sprintf("%s/sample-object", [bucket_arn])}

as_array(v) := v { is_array(v) } else := [v]

resource_covers(stmt, arn) {
    glob.match(as_array(stmt.Resource)[_], [], arn)
}

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

# A Deny for everyone on all S3 actions whose only condition is a
# StringNotEquals on s3:DataAccessPointArn allows exactly the listed access
# points.
ap_condition_values(stmt) := vals {
    stmt.Effect == "Deny"
    covers_all_s3(stmt.Action)
    applies_to_everyone(stmt.Principal)
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    restriction_operators[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "s3:dataaccesspointarn"
    vals := as_array(val)
}

restricted_scope[arn] {
    stmt := statements[_]
    ap_condition_values(stmt)
    arn := scope_arns[_]
    resource_covers(stmt, arn)
}

allowed_by_policy[ap] {
    ap := ap_condition_values(statements[_])[_]
}

has_ap_restriction {
    count(restricted_scope) == count(scope_arns)
}

unauthorized_aps := allowed_by_policy - authorized_access_points

result := "skip" {
    not fetch_ok
} else := "fail" {
    not has_ap_restriction
} else := "fail" {
    count(unauthorized_aps) > 0
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so access points are not restricted." {
    result == "fail"
    input.bucketPolicy == null
} else := sprintf("Bucket policy allows unauthorized access point(s): %v", [unauthorized_aps]) {
    result == "fail"
    count(unauthorized_aps) > 0
} else := "Bucket policy has no access point restriction that applies to all principals and all S3 actions on every object, with no other condition." {
    result == "fail"
} else := "Bucket policy restricts access to authorized access points."

expectedConfiguration := sprintf("Bucket policy must contain a Deny for all principals and all S3 actions on every object in the bucket whose only condition is StringNotEquals on s3:DataAccessPointArn, listing only authorized access points: %v", [authorized_access_points])
