package wiz

# 1. PASS: Deny PutObjectAcl for public-read (Standard)
test_block_acl_pass {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObjectAcl\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":[\"public-read\",\"public-read-write\"]}}}]}"
    }
}

# 2. PASS: Deny s3:* for public-read (Broader Action)
test_block_acl_pass_broad_action {
    result == "pass" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"public-read\"}}}]}"
    }
}

# 3. FAIL: No Policy (Implicit Allow)
test_block_acl_fail_no_policy {
    result == "fail" with input as {}
}

# 4. FAIL: Deny exists but checks wrong header (e.g. source IP)
test_block_acl_fail_wrong_condition {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObjectAcl\",\"Resource\":\"*\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"1.2.3.4\"}}}]}"
    }
}

# 5. FAIL: Deny exists but only for 'private' ACL (useless)
test_block_acl_fail_wrong_value {
    result == "fail" with input as {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObjectAcl\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"private\"}}}]}"
    }
}

# 6. SKIP: Missing Input (Null)
test_block_acl_skip {
    result == "skip" with input as null
}