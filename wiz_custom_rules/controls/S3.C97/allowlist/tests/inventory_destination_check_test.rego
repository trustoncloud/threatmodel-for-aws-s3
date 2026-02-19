package wiz

# 1. PASS: Destination is Authorized
test_inventory_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_inventory_destinations": ["arn:aws:s3:::secure-logs"]
        },
        "properties": {
            "inventoryConfigurations": [
                {
                    "Id": "DailyReport",
                    "Destination": { "S3BucketDestination": { "Bucket": "arn:aws:s3:::secure-logs" } }
                }
            ]
        }
    }
}

# 2. PASS: No Inventory Configured (Implicit Pass)
test_inventory_pass_no_config {
    result == "pass" with input as {
        "parameters": { "authorized_inventory_destinations": ["arn:aws:s3:::secure-logs"] },
        "properties": {
            # Empty list or null is fine
            "inventoryConfigurations": []
        }
    }
}

# 3. FAIL: Destination is Unauthorized
test_inventory_fail_unauthorized {
    result == "fail" with input as {
        "parameters": {
            "authorized_inventory_destinations": ["arn:aws:s3:::secure-logs"]
        },
        "properties": {
            "inventoryConfigurations": [
                {
                    "Id": "LeakyReport",
                    "Destination": { "S3BucketDestination": { "Bucket": "arn:aws:s3:::attacker-bucket" } }
                }
            ]
        }
    }
}

# 4. FAIL: Mixed (One good, one bad)
test_inventory_fail_mixed {
    result == "fail" with input as {
        "parameters": {
            "authorized_inventory_destinations": ["arn:aws:s3:::secure-logs"]
        },
        "properties": {
            "inventoryConfigurations": [
                { "Destination": { "S3BucketDestination": { "Bucket": "arn:aws:s3:::secure-logs" } } },
                { "Destination": { "S3BucketDestination": { "Bucket": "arn:aws:s3:::untrusted-bucket" } } }
            ]
        }
    }
}

# 5. SKIP: Missing Input
test_inventory_skip {
    result == "skip" with input as null
}