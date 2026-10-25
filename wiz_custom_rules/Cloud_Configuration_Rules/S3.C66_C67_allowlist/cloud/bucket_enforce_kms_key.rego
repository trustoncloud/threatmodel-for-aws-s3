package wiz

# --- Configuration ---
authorized_kms_key_ids := {
    "arn:aws:kms:us-east-1:123456789012:key/authorized-key",
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

covers_put_object(action) { action == "s3:PutObject" }
covers_put_object(action) { action == "s3:*" }
covers_put_object(action) { action == "*" }
covers_put_object(action) { action[_] == "s3:PutObject" }
covers_put_object(action) { action[_] == "s3:*" }
covers_put_object(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

# The deny must reach every object in the bucket; the sample object ARN stands
# in for any key.
bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

object_arn := sprintf("%s/sample-object", [bucket_arn])

as_array(v) := v { is_array(v) } else := [v]

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

# A Deny on PutObject for everyone on every object whose only condition is a
# StringNotEquals on the KMS key header, listing only authorized keys.
enforces_authorized_key {
    statement := statements[_]
    statement.Effect == "Deny"
    covers_put_object(statement.Action)
    applies_to_everyone(statement.Principal)
    glob.match(as_array(statement.Resource)[_], [], object_arn)
    count(statement.Condition) == 1
    conditions := statement.Condition[operator]
    restriction_operators[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "s3:x-amz-server-side-encryption-aws-kms-key-id"
    vals := {v | v := as_array(val)[_]}
    count(vals) > 0
    count(vals - authorized_kms_key_ids) == 0
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    not enforces_authorized_key
}

# --- Metadata ---
currentConfiguration := "Bucket has no bucket policy, so PutObject requests with any KMS key are accepted." {
    result == "fail"
    input.bucketPolicy == null
} else := "Bucket policy has no Deny restricting PutObject to the authorized KMS key(s) for all principals on every object, with no other condition." {
    result == "fail"
} else := "Bucket policy enforces the authorized KMS key(s) for PutObject."

expectedConfiguration := sprintf("Bucket policy must Deny s3:PutObject for all principals on every object when s3:x-amz-server-side-encryption-aws-kms-key-id is not in the authorized set, with no other condition: %v", [authorized_kms_key_ids])
