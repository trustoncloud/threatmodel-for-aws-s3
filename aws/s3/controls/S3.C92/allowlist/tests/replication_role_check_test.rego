package wiz

# 1. PASS: Replication Enabled with Authorized Role
test_replication_role_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_replication_roles": ["arn:aws:iam::123456789012:role/S3ReplicationRole"]
        },
        "properties": {
            "replicationConfiguration": {
                "role": "arn:aws:iam::123456789012:role/S3ReplicationRole"
            }
        }
    }
}

# 2. PASS: Replication Not Configured (Implicit Pass)
test_replication_role_pass_no_config {
    result == "pass" with input as {
        "parameters": { "authorized_replication_roles": ["role/good"] },
        "properties": {}
    }
}

# 3. FAIL: Unauthorized Role
test_replication_role_fail_bad_role {
    result == "fail" with input as {
        "parameters": {
            "authorized_replication_roles": ["arn:aws:iam::123456789012:role/S3ReplicationRole"]
        },
        "properties": {
            "replicationConfiguration": {
                "role": "arn:aws:iam::123456789012:role/AdminAccess" # FAIL
            }
        }
    }
}

# 4. FAIL: Role field exists but is empty (Invalid Config)
test_replication_role_fail_empty {
    result == "fail" with input as {
        "parameters": {
            "authorized_replication_roles": ["role/good"]
        },
        "properties": {
            "replicationConfiguration": {
                "role": ""
            }
        }
    }
}

# 5. SKIP: Missing Input (Null)
test_replication_role_skip {
    result == "skip" with input as null
}