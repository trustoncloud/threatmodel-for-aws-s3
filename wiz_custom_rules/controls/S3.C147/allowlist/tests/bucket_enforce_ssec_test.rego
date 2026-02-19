package wiz

# 1. PASS: Target Bucket correctly enforces SSE-C
test_ssec_pass_enforced {
    result == "pass" with input as {
        "name": "sensitive-data-bucket",
        "parameters": {
            "target_ssec_buckets": ["sensitive-data-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption-customer-algorithm\":\"AES256\"}}}]}"
    }
}

# 2. PASS: Non-Target Bucket (Standard Bucket) - Should Pass regardless of policy
test_ssec_pass_ignored {
    result == "pass" with input as {
        "name": "standard-logs-bucket",
        "parameters": {
            "target_ssec_buckets": ["sensitive-data-bucket"]
        },
        # No policy, or standard policy, doesn't matter
        "policy": null
    }
}

# 3. FAIL: Target Bucket lacks enforcement
test_ssec_fail_target_missing_rule {
    result == "fail" with input as {
        "name": "sensitive-data-bucket",
        "parameters": {
            "target_ssec_buckets": ["sensitive-data-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
    }
}

# 4. FAIL: Target Bucket checks wrong header (e.g., KMS)
test_ssec_fail_wrong_check {
    result == "fail" with input as {
        "name": "sensitive-data-bucket",
        "parameters": {
            "target_ssec_buckets": ["sensitive-data-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption\":\"aws:kms\"}}}]}"
    }
}

# 5. FAIL: Target Bucket has no policy at all
test_ssec_fail_no_policy {
    result == "fail" with input as {
        "name": "sensitive-data-bucket",
        "parameters": { "target_ssec_buckets": ["sensitive-data-bucket"] },
        "policy": null
    }
}

# 6. SKIP: Missing Input
test_ssec_skip {
    result == "skip" with input as null
}