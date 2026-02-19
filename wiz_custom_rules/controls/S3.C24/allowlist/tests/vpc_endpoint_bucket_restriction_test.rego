package wiz

# 1. PASS: Policy allows ONLY authorized bucket
test_bucket_restrict_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_buckets": ["arn:aws:s3:::my-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"arn:aws:s3:::my-bucket\"}]}"
    }
}

# 2. PASS: Policy allows Bucket AND Objects (Both covered by logic)
test_bucket_restrict_pass_objects {
    result == "pass" with input as {
        "parameters": {
            "authorized_buckets": ["arn:aws:s3:::my-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":[\"arn:aws:s3:::my-bucket\", \"arn:aws:s3:::my-bucket/*\"]}]}"
    }
}

# 3. FAIL: Policy allows * (Wildcard)
test_bucket_restrict_fail_wildcard {
    result == "fail" with input as {
        "parameters": {
            "authorized_buckets": ["arn:aws:s3:::my-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
}

# 4. FAIL: Policy allows Unauthorized Bucket
test_bucket_restrict_fail_rogue {
    result == "fail" with input as {
        "parameters": {
            "authorized_buckets": ["arn:aws:s3:::my-bucket"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":[\"arn:aws:s3:::my-bucket\", \"arn:aws:s3:::evil-bucket\"]}]}"
    }
}

# 5. FAIL: No Policy (Implicit Allow *)
test_bucket_restrict_fail_no_policy {
    result == "fail" with input as {
        "parameters": { "authorized_buckets": ["arn:aws:s3:::my-bucket"] },
        "policy": null
    }
}

# 6. SKIP: Missing Input
test_bucket_restrict_skip {
    result == "skip" with input as null
}