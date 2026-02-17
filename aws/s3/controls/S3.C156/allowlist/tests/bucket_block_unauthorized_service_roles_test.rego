package wiz

# 1. PASS: Policy blocks everyone EXCEPT authorized role
test_role_block_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_service_roles": ["arn:aws:iam::123:role/GoodRole"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalArn\":\"arn:aws:iam::123:role/GoodRole\"}}}]}"
    }
}

# 2. PASS: Policy allows Subset (Stricter than parameter list)
test_role_block_pass_subset {
    result == "pass" with input as {
        "parameters": {
            "authorized_service_roles": ["arn:aws:iam::123:role/GoodRole", "arn:aws:iam::123:role/BackupRole"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalArn\":\"arn:aws:iam::123:role/GoodRole\"}}}]}"
    }
}

# 3. FAIL: Policy allows an Unauthorized Role (Rogue Role)
test_role_block_fail_rogue {
    result == "fail" with input as {
        "parameters": {
            "authorized_service_roles": ["arn:aws:iam::123:role/GoodRole"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalArn\":\"arn:aws:iam::123:role/BAD_ROLE\"}}}]}"
    }
}

# 4. FAIL: Policy allows Mixed (One good, one bad)
test_role_block_fail_mixed {
    result == "fail" with input as {
        "parameters": {
            "authorized_service_roles": ["arn:aws:iam::123:role/GoodRole"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalArn\":[\"arn:aws:iam::123:role/GoodRole\", \"arn:aws:iam::123:role/BAD_ROLE\"]}}}]}"
    }
}

# 5. FAIL: No Policy (Implicit Allow for authenticated users in account)
test_role_block_fail_no_policy {
    result == "fail" with input as {
        "parameters": { "authorized_service_roles": ["arn:aws:iam::123:role/GoodRole"] },
        "policy": null
    }
}

# 6. FAIL: Restriction exists but wrong key (e.g. SourceArn instead of PrincipalArn)
test_role_block_fail_wrong_key {
    result == "fail" with input as {
        "parameters": { "authorized_service_roles": ["arn:aws:iam::123:role/GoodRole"] },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceArn\":\"arn:aws:iam::123:role/GoodRole\"}}}]}"
    }
}

# 7. SKIP: Missing Input
test_role_block_skip {
    result == "skip" with input as null
}