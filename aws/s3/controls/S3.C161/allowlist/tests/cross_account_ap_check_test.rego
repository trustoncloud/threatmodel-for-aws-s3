package wiz

# 1. PASS: Authorized Bucket + Authorized Account
test_ap_check_pass {
    result == "pass" with input as {
        "accountId": "111122223333",
        "properties": {
            "bucket": "trusted-bucket",
            "bucketAccountId": "111122223333"
        },
        "parameters": {
            "authorized_buckets": ["trusted-bucket"],
            "authorized_accounts": ["111122223333"]
        }
    }
}

# 2. PASS: Local AP (Implicit Account ID match)
test_ap_check_pass_local {
    result == "pass" with input as {
        "accountId": "111122223333",
        "properties": {
            "bucket": "trusted-bucket"
            # bucketAccountId missing -> defaults to input.accountId
        },
        "parameters": {
            "authorized_buckets": ["trusted-bucket"],
            "authorized_accounts": ["111122223333"]
        }
    }
}

# 3. FAIL: Unauthorized Bucket Name
test_ap_check_fail_bucket {
    result == "fail" with input as {
        "accountId": "111122223333",
        "properties": {
            "bucket": "rogue-bucket",
            "bucketAccountId": "111122223333"
        },
        "parameters": {
            "authorized_buckets": ["trusted-bucket"],
            "authorized_accounts": ["111122223333"]
        }
    }
}

# 4. FAIL: Authorized Bucket, but Unauthorized Account (Impersonation/Misconfig)
test_ap_check_fail_account {
    result == "fail" with input as {
        "accountId": "111122223333",
        "properties": {
            "bucket": "trusted-bucket",
            "bucketAccountId": "999988887777" # Untrusted Account
        },
        "parameters": {
            "authorized_buckets": ["trusted-bucket"],
            "authorized_accounts": ["111122223333"]
        }
    }
}

# 5. SKIP: Missing Input
test_ap_check_skip {
    result == "skip" with input as null
}