package wiz

# --- Logic ---
default result := "pass"

replication_rules := input.bucketReplication.ReplicationConfiguration.Rules

fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketReplication.result == "Success"
}

metrics_enabled(rule) {
    rule.Destination.Metrics.Status == "Enabled"
}

rules_without_metrics[rule_id] {
    rule := replication_rules[_]
    not metrics_enabled(rule)
    rule_id := object.get(rule, "ID", "unnamed")
}

result := "skip" {
    not fetch_ok
} else := "skip" {
    input.bucketReplication == null
} else := "fail" {
    count(rules_without_metrics) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Replication rules without metrics enabled: %v", [rules_without_metrics]) {
    result == "fail"
} else := "All replication rules have metrics enabled, or replication is not configured."

expectedConfiguration := "Every replication rule must have Destination.Metrics.Status set to Enabled."
