package wiz

# 1. PASS: Deny via aws:SecureTransport "false"
test_ssl_pass_bool {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bucket/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 2. PASS: Deny via s3:TlsVersion < 1.2
test_ssl_pass_tls {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bucket/*\",\"Condition\":{\"NumericLessThan\":{\"s3:TlsVersion\":1.2}}}]}"
    }
}

# 3. FAIL: No Policy
test_ssl_fail_no_policy {
    result == "fail" with input as {}
}

# 4. FAIL: Allow only (No Deny)
test_ssl_fail_allow_only {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bucket/*\"}]}"
    }
}

# 5. FAIL: Limited Action (PutObject only)
test_ssl_fail_limited_action {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 6. SKIP: Malformed/Missing Input
test_ssl_skip_missing {
    result == "skip" with input as null
}