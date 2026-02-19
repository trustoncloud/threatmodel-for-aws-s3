package wiz

# 1. PASS: Policy Denies * via aws:SecureTransport (Standard Array)
test_secure_transport_bool_pass {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 2. PASS: Policy Denies s3:* via TLS Version (Object Format)
test_secure_transport_tls_pass_object {
    result == "pass" with input as {
        "policy": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "NumericLessThan": {
                        "s3:TlsVersion": 1.2
                    }
                }
            }
        }
    }
}

# 3. PASS: Policy Denies ["s3:*"] List via Boolean False
test_secure_transport_bool_raw_false {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":[\"s3:*\"],\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":false}}}]}"
    }
}

# 4. FAIL: No Policy
test_fail_no_policy {
    result == "fail" with input as {}
}

# 5. FAIL: Allow only (No Deny)
test_fail_allow_only {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
}

# 6. FAIL: Limited Action (Not * or s3:*)
test_fail_limited_action {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 7. FAIL: Wrong TLS Version
test_fail_wrong_tls {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"NumericLessThan\":{\"s3:TlsVersion\":1.0}}}]}"
    }
}

# 8. SKIP: Malformed/Missing Input
test_skip_missing_input {
    result == "skip" with input as null
}