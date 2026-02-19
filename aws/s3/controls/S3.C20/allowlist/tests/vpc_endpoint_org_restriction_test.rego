package wiz

# 1. PASS: Policy restricts to "o-good", which is authorized
test_allowlist_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_orgs": ["o-good", "o-partner"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"o-good\"}}}]}"
    }
}

# 2. PASS: Policy restricts to ["o-good", "o-partner"] (Both authorized)
test_allowlist_pass_multiple {
    result == "pass" with input as {
        "parameters": {
            "authorized_orgs": ["o-good", "o-partner", "o-extra"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":[\"o-good\", \"o-partner\"]}}}]}"
    }
}

# 3. FAIL: Policy restricts to "o-bad", which is NOT authorized
test_allowlist_fail_unauthorized {
    result == "fail" with input as {
        "parameters": {
            "authorized_orgs": ["o-good"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"o-bad\"}}}]}"
    }
}

# 4. FAIL: Policy has no restriction
test_allowlist_fail_no_restriction {
    result == "fail" with input as {
        "parameters": {
            "authorized_orgs": ["o-good"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
}

# 5. FAIL: Policy restricts to Mixed (one good, one bad)
test_allowlist_fail_mixed {
    result == "fail" with input as {
        "parameters": {
            "authorized_orgs": ["o-good"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":[\"o-good\", \"o-bad\"]}}}]}"
    }
}

# 6. SKIP: Input is Null (Simulates missing resource data)
test_allowlist_skip {
    result == "skip" with input as null
}