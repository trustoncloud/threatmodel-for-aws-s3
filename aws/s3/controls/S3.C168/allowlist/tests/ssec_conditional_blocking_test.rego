package wiz

# 1. PASS: Bucket REQUIRES SSE-C, and it is NOT blocked.
test_ssec_pass_required_allowed {
    result == "pass" with input as {
        "name": "sensitive-ssec-bucket",
        "parameters": {
            "buckets_requiring_ssec": ["sensitive-ssec-bucket"]
        },
        # Policy is generic or enforces usage, but definitely does NOT block availability.
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
    }
}

# 2. PASS: Bucket DOES NOT require SSE-C, and it IS blocked.
test_ssec_pass_not_required_blocked {
    result == "pass" with input as {
        "name": "standard-bucket",
        "parameters": {
            "buckets_requiring_ssec": ["sensitive-ssec-bucket"]
        },
        # Policy strictly blocks SSE-C usage
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"Null\":{\"s3:x-amz-server-side-encryption-customer-algorithm\":\"false\"}}}]}"
    }
}

# 3. FAIL: Bucket REQUIRES SSE-C, but Policy BLOCKS it.
test_ssec_fail_required_blocked {
    result == "fail" with input as {
        "name": "sensitive-ssec-bucket",
        "parameters": {
            "buckets_requiring_ssec": ["sensitive-ssec-bucket"]
        },
        # Policy accidentally blocks the needed encryption method
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"Null\":{\"s3:x-amz-server-side-encryption-customer-algorithm\":\"false\"}}}]}"
    }
}

# 4. FAIL: Bucket DOES NOT require SSE-C, but Policy ALLOWS it (No block).
test_ssec_fail_not_required_allowed {
    result == "fail" with input as {
        "name": "standard-bucket",
        "parameters": {
            "buckets_requiring_ssec": ["sensitive-ssec-bucket"]
        },
        # Policy is open, allowing users to use custom keys when they shouldn't.
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
    }
}

# 5. SKIP: Missing Input
test_ssec_skip {
    result == "skip" with input as null
}