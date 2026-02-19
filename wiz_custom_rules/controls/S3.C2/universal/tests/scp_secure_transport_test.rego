package wiz

# 1. PASS: SCP Denies unencrypted S3 traffic
test_scp_pass {
    result == "pass" with input as {
        "type": "SERVICE_CONTROL_POLICY",
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 2. PASS: SCP Denies old TLS versions
test_scp_pass_tls {
    result == "pass" with input as {
        "type": "SERVICE_CONTROL_POLICY",
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"NumericLessThan\":{\"s3:TlsVersion\":1.2}}}]}"
    }
}

# 3. FAIL: SCP exists but lacks the restriction (Allow only)
test_scp_fail_allow_only {
    result == "fail" with input as {
        "type": "SERVICE_CONTROL_POLICY",
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
}

# 4. FAIL: Principal is present (Syntax error for SCP, but if present and logic fails)
# Note: Real SCPs fail to save if Principal is present, but we check logic robustness
test_scp_fail_limited_action {
    result == "fail" with input as {
        "type": "SERVICE_CONTROL_POLICY",
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 5. SKIP: Not an SCP (e.g. TAG_POLICY)
test_scp_skip_wrong_type {
    result == "skip" with input as {
        "type": "TAG_POLICY",
        "content": "{}"
    }
}