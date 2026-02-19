package wiz

# 1. PASS: Policy allows ONLY authorized VPC
test_vpc_restrict_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_vpcs": ["vpc-111"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"vpc-111\"}}}]}"
    }
}

# 2. PASS: Policy allows Subset (Stricter than parameter list)
test_vpc_restrict_pass_subset {
    result == "pass" with input as {
        "parameters": {
            "authorized_vpcs": ["vpc-111", "vpc-222"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"vpc-111\"}}}]}"
    }
}

# 3. FAIL: Policy allows Unauthorized VPC
test_vpc_restrict_fail_rogue {
    result == "fail" with input as {
        "parameters": {
            "authorized_vpcs": ["vpc-111"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"vpc-666\"}}}]}"
    }
}

# 4. FAIL: Policy allows Mixed (One good, one bad)
# FIXED: Added missing escape characters for vpc-666
test_vpc_restrict_fail_mixed {
    result == "fail" with input as {
        "parameters": {
            "authorized_vpcs": ["vpc-111"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":[\"vpc-111\", \"vpc-666\"]}}}]}"
    }
}

# 5. FAIL: No Policy (No Restriction)
test_vpc_restrict_fail_no_policy {
    result == "fail" with input as {
        "parameters": { "authorized_vpcs": ["vpc-111"] },
        "policy": null
    }
}

# 6. FAIL: Restriction exists but wrong key (e.g. SourceIp instead of SourceVpc)
test_vpc_restrict_fail_wrong_key {
    result == "fail" with input as {
        "parameters": { "authorized_vpcs": ["vpc-111"] },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceIp\":\"1.2.3.4\"}}}]}"
    }
}

# 7. SKIP: Missing Input
test_vpc_restrict_skip {
    result == "skip" with input as null
}