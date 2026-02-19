package wiz

# 1. PASS: OAI (Legacy) matches Authorized ID
test_cloudfront_pass_oai {
    result == "pass" with input as {
        "parameters": {
            "authorized_cloudfront_ids": ["E123456789"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123456789\"},\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
    }
}

# 2. PASS: OAC (Modern) matches Authorized Distribution ID
test_cloudfront_pass_oac {
    result == "pass" with input as {
        "parameters": {
            "authorized_cloudfront_ids": ["E987654321"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudfront.amazonaws.com\"},\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudfront::111122223333:distribution/E987654321\"}}}]}"
    }
}

# 3. FAIL: OAI Identity is NOT authorized
test_cloudfront_fail_rogue_oai {
    result == "fail" with input as {
        "parameters": {
            "authorized_cloudfront_ids": ["E_GOOD"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E_BAD\"},\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
    }
}

# 4. FAIL: OAC Distribution is NOT authorized
test_cloudfront_fail_rogue_oac {
    result == "fail" with input as {
        "parameters": {
            "authorized_cloudfront_ids": ["E_GOOD"]
        },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudfront.amazonaws.com\"},\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudfront::111122223333:distribution/E_BAD\"}}}]}"
    }
}

# 5. PASS: Policy has no CloudFront access (Secure by default)
test_cloudfront_pass_no_access {
    result == "pass" with input as {
        "parameters": { "authorized_cloudfront_ids": ["E_GOOD"] },
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123:user/Bob\"},\"Action\":\"s3:*\"}]}"
    }
}

# 6. SKIP: Missing Input
test_cloudfront_skip {
    result == "skip" with input as null
}