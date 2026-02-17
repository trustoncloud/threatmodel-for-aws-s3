package wiz

# 1. PASS: Restriction via Org ID
test_universal_pass_org_id {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"o-123456\"}}}]}"
    }
}

# 2. PASS: Restriction via OU Path
test_universal_pass_ou_path {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgPaths\":\"o-123/r-456/ou-789\"}}}]}"
    }
}

# 3. FAIL: No Policy (Implicit Allow All)
test_universal_fail_no_policy {
    result == "fail" with input as {}
}

# 4. FAIL: Allow Only (No Deny restriction)
test_universal_fail_allow_only {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
}

# 5. FAIL: Deny exists but unrelated condition (e.g., SecureTransport only)
test_universal_fail_unrelated_deny {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
}

# 6. SKIP: Null Input
test_universal_skip {
    result == "skip" with input as null
}