package wiz

# 1. PASS: Rule has Metrics Enabled
test_metrics_pass {
    result == "pass" with input as {
        "properties": {
            "replicationConfiguration": {
                "Rules": [
                    { "ID": "Rule1", "Status": "Enabled", "Metrics": { "Status": "Enabled" } }
                ]
            }
        }
    }
}

# 2. PASS: Multiple Rules, All Enabled
test_metrics_pass_multiple {
    result == "pass" with input as {
        "properties": {
            "replicationConfiguration": {
                "Rules": [
                    { "ID": "Rule1", "Metrics": { "Status": "Enabled" } },
                    { "ID": "Rule2", "Metrics": { "Status": "Enabled" } }
                ]
            }
        }
    }
}

# 3. PASS: No Replication Configured (Control is N/A, so Pass)
test_metrics_pass_no_replication {
    result == "pass" with input as {
        "properties": {
            # replicationConfiguration is missing or empty
        }
    }
}

# 4. FAIL: Metrics Disabled explicitly
test_metrics_fail_disabled {
    result == "fail" with input as {
        "properties": {
            "replicationConfiguration": {
                "Rules": [
                    { "ID": "Rule1", "Metrics": { "Status": "Disabled" } }
                ]
            }
        }
    }
}

# 5. FAIL: Metrics block missing entirely from rule
test_metrics_fail_missing_field {
    result == "fail" with input as {
        "properties": {
            "replicationConfiguration": {
                "Rules": [
                    { "ID": "Rule1", "Status": "Enabled" } 
                    # Metrics block missing
                ]
            }
        }
    }
}

# 6. FAIL: Mixed (One Good, One Bad)
test_metrics_fail_mixed {
    result == "fail" with input as {
        "properties": {
            "replicationConfiguration": {
                "Rules": [
                    { "ID": "GoodRule", "Metrics": { "Status": "Enabled" } },
                    { "ID": "BadRule", "Metrics": { "Status": "Disabled" } }
                ]
            }
        }
    }
}

# 7. SKIP: Input Null
test_metrics_skip {
    result == "skip" with input as null
}