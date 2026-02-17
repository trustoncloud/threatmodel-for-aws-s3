package wiz

# 1. PASS: Policy grants access only to authorized role
test_principal_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_principals": ["arn:aws:iam::111:role/Admin"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111:role/Admin\"},\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
    }
}

# 2. PASS: Policy has Allow for Service (Not checked by this rule) and Authorized IAM
test_principal_pass_service_ignored {
    result == "pass" with input as {
        "parameters": {
            "authorized_principals": ["arn:aws:iam::111:role/Admin"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111:role/Admin\"},\"Action\":\"s3:*\"},{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"s3:Get*\"}]}"
    }
}

# 3. FAIL: Unauthorized Principal found
test_principal_fail_rogue {
    result == "fail" with input as {
        "parameters": {
            "authorized_principals": ["arn:aws:iam::111:role/Admin"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::666:user/Hacker\"},\"Action\":\"s3:*\"}]}"
    }
}

# 4. FAIL: Mixed (One good, one bad)
# FIXED: Added missing escape characters for the second ARN
test_principal_fail_mixed {
    result == "fail" with input as {
        "parameters": {
            "authorized_principals": ["arn:aws:iam::111:role/Admin"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam::111:role/Admin\", \"arn:aws:iam::666:user/Bad\"]},\"Action\":\"s3:*\"}]}"
    }
}

# 5. FAIL: Wildcard Principal (Public Access)
test_principal_fail_wildcard {
    result == "fail" with input as {
        "parameters": {
            "authorized_principals": ["arn:aws:iam::111:role/Admin"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\"}]}"
    }
}

# 6. SKIP: Missing Input
test_principal_skip {
    result == "skip" with input as null
}