package wiz

# 1. PASS: Destination is Authorized
test_rep_dest_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_replication_destinations": ["arn:aws:s3:::dr-bucket"]
        },
        "properties": {
            "replicationConfiguration": {
                "rules": [
                    { "id": "Rule1", "destination": { "bucket": "arn:aws:s3:::dr-bucket" } }
                ]
            }
        }
    }
}

# 2. PASS: No Replication Configured (Implicit Pass)
test_rep_dest_pass_no_config {
    result == "pass" with input as {
        "parameters": { "authorized_replication_destinations": ["arn:aws:s3:::dr-bucket"] },
        "properties": {}
    }
}

# 3. FAIL: Unauthorized Destination
test_rep_dest_fail_rogue {
    result == "fail" with input as {
        "parameters": {
            "authorized_replication_destinations": ["arn:aws:s3:::dr-bucket"]
        },
        "properties": {
            "replicationConfiguration": {
                "rules": [
                    { "id": "Rule1", "destination": { "bucket": "arn:aws:s3:::hacker-bucket" } }
                ]
            }
        }
    }
}

# 4. FAIL: Mixed (One good, one bad)
test_rep_dest_fail_mixed {
    result == "fail" with input as {
        "parameters": {
            "authorized_replication_destinations": ["arn:aws:s3:::dr-bucket"]
        },
        "properties": {
            "replicationConfiguration": {
                "rules": [
                    { "id": "GoodRule", "destination": { "bucket": "arn:aws:s3:::dr-bucket" } },
                    { "id": "BadRule", "destination": { "bucket": "arn:aws:s3:::leaky-bucket" } }
                ]
            }
        }
    }
}

# 5. SKIP: Missing Input (Null)
test_rep_dest_skip {
    result == "skip" with input as null
}