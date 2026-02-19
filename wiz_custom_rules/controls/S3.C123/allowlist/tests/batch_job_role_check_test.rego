package wiz

# 1. PASS: Job Role is Authorized
test_batch_role_pass {
    result == "pass" with input as {
        "parameters": {
            "authorized_job_roles": ["arn:aws:iam::123:role/SafeRole"]
        },
        "properties": {
            "containerProperties": {
                "jobRoleArn": "arn:aws:iam::123:role/SafeRole"
            }
        }
    }
}

# 2. FAIL: Job Role is Unauthorized
test_batch_role_fail {
    result == "fail" with input as {
        "parameters": {
            "authorized_job_roles": ["arn:aws:iam::123:role/SafeRole"]
        },
        "properties": {
            "containerProperties": {
                "jobRoleArn": "arn:aws:iam::123:role/MaliciousRole"
            }
        }
    }
}

# 3. PASS: No Job Role Configured (Implies minimal/no permissions)
test_batch_role_pass_no_role {
    result == "pass" with input as {
        "parameters": {
            "authorized_job_roles": ["arn:aws:iam::123:role/SafeRole"]
        },
        "properties": {
            "containerProperties": {
                # jobRoleArn is missing
                "image": "my-image"
            }
        }
    }
}

# 4. FAIL: Malformed Input (No container properties)
test_batch_role_fail_malformed {
    result == "fail" with input as {
        "properties": {}
    }
}

# 5. SKIP: Missing Input
test_batch_role_skip {
    result == "skip" with input as null
}