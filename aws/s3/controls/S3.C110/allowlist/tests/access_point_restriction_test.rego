package wiz

# 1. PASS: Policy allows ONLY authorized AP
test_ap_restrict_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_access_points": ["arn:aws:s3:us-east-1:123:accesspoint/finance"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:DataAccessPointArn\":\"arn:aws:s3:us-east-1:123:accesspoint/finance\"}}}]}"
    }
}

# 2. PASS: Policy allows Subset (Stricter than parameter list)
test_ap_restrict_pass_subset {
    result == "pass" with input as {
        "parameters": {
            "authorized_access_points": [
                "arn:aws:s3:us-east-1:123:accesspoint/finance",
                "arn:aws:s3:us-east-1:123:accesspoint/hr"
            ]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:DataAccessPointArn\":\"arn:aws:s3:us-east-1:123:accesspoint/finance\"}}}]}"
    }
}

# 3. FAIL: Policy allows Unauthorized AP
test_ap_restrict_fail_rogue {
    result == "fail" with input as {
        "parameters": {
            "authorized_access_points": ["arn:aws:s3:us-east-1:123:accesspoint/finance"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:DataAccessPointArn\":\"arn:aws:s3:us-east-1:123:accesspoint/ROGUE\"}}}]}"
    }
}

# 4. FAIL: No Policy (No Restriction)
test_ap_restrict_fail_no_policy {
    result == "fail" with input as {
        "parameters": { "authorized_access_points": ["arn:aws:s3:us-east-1:123:accesspoint/finance"] },
        "policy": null
    }
}

# 5. FAIL: Restriction exists but wrong key
test_ap_restrict_fail_wrong_key {
    result == "fail" with input as {
        "parameters": { "authorized_access_points": ["arn:aws:s3:us-east-1:123:accesspoint/finance"] },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"vpc-123\"}}}]}"
    }
}

# 6. SKIP: Missing Input
test_ap_restrict_skip {
    result == "skip" with input as null
}