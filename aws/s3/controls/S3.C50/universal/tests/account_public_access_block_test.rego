package wiz

# 1. PASS: All 4 flags are True
test_account_bpa_pass {
    result == "pass" with input as {
        "properties": {
            "blockPublicAcls": true,
            "ignorePublicAcls": true,
            "blockPublicPolicy": true,
            "restrictPublicBuckets": true
        }
    }
}

# 2. FAIL: One flag is False (e.g., restrictPublicBuckets)
test_account_bpa_fail_one_false {
    result == "fail" with input as {
        "properties": {
            "blockPublicAcls": true,
            "ignorePublicAcls": true,
            "blockPublicPolicy": true,
            "restrictPublicBuckets": false # FAIL
        }
    }
}

# 3. FAIL: All flags False
test_account_bpa_fail_all_false {
    result == "fail" with input as {
        "properties": {
            "blockPublicAcls": false,
            "ignorePublicAcls": false,
            "blockPublicPolicy": false,
            "restrictPublicBuckets": false
        }
    }
}

# 4. FAIL: Configuration exists but is empty/missing keys
test_account_bpa_fail_missing_keys {
    result == "fail" with input as {
        "properties": {
            "blockPublicAcls": true
            # Others missing
        }
    }
}

# 5. SKIP: Missing Input (Null)
test_account_bpa_skip {
    result == "skip" with input as null
}