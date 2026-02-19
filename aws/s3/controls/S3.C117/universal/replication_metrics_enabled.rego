package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Get Replication Configuration (Safe Access)
# Returns the rules list, or empty list if null/missing
replication_rules := rules {
    input.properties.replicationConfiguration.Rules != null
    rules := input.properties.replicationConfiguration.Rules
} else := []

# Helper: Check if a rule has Metrics enabled
is_metrics_enabled(rule) {
    rule.Metrics.Status == "Enabled"
}

# Helper: Find rules that do NOT have metrics enabled
rules_without_metrics[rule_id] {
    # Iterate over rules using implicit index
    rule := replication_rules[_]
    
    # Check if metrics are missing or disabled
    not is_metrics_enabled(rule)
    
    # Capture ID for the error message
    rule_id := rule.ID
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "pass" {
    # If there are no replication rules, the requirement for "replicated buckets" doesn't apply.
    # So this is a Pass (Not Applicable).
    count(replication_rules) == 0
} else := "fail" {
    # Fail if we found any rule without metrics
    count(rules_without_metrics) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Replication rules without metrics enabled: %v", [rules_without_metrics]) {
    result == "fail"
} else := "All replication rules have metrics enabled."

expectedConfiguration := "All S3 Replication rules must have 'Metrics.Status' set to 'Enabled'."