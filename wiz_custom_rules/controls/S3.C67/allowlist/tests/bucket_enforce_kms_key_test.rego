package wiz

# 1. PASS: Policy correctly enforces the Authorized Key
test_kms_enforce_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_kms_key_id": "arn:aws:kms:us-east-1:123:key/secure-key"
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption-aws-kms-key-id\":\"arn:aws:kms:us-east-1:123:key/secure-key\"}}}]}"
    }
}

# 2. FAIL: Policy enforces the WRONG key
test_kms_enforce_fail_wrong_key {
    result == "fail" with input as {
        "parameters": {
            "authorized_kms_key_id": "arn:aws:kms:us-east-1:123:key/secure-key"
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption-aws-kms-key-id\":\"arn:aws:kms:us-east-1:123:key/OLD-KEY\"}}}]}"
    }
}

# 3. FAIL: Policy Denies PutObject but lacks the Key condition (Denies everything)
# Technically this blocks the unauthorized key, but it blocks *everything*, so it's not the specific control we are looking for. 
# Our logic looks for the specific condition key.
test_kms_enforce_fail_no_condition {
    result == "fail" with input as {
        "parameters": { "authorized_kms_key_id": "key/1" },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\"}]}"
    }
}

# 4. FAIL: No Policy
test_kms_enforce_fail_no_policy {
    result == "fail" with input as {
        "parameters": { "authorized_kms_key_id": "key/1" },
        "policy": null
    }
}

# 5. SKIP: Missing Input (Null)
test_kms_enforce_skip {
    result == "skip" with input as null
}