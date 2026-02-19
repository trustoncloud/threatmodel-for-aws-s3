package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Check if Replication is enabled
has_replication {
    input.properties.replicationConfiguration != null
}

# Helper: Get Replication Rules
# S3 Replication Config contains a list of rules.
replication_rules[rule] {
    # It might be a single object or an array depending on provider schema, 
    # but standard CloudFormation/Wiz schema usually lists them under 'rules'.
    input.properties.replicationConfiguration.rules != null
    rule := input.properties.replicationConfiguration.rules[_]
}

# Helper: Get Authorized Destinations from Parameters
# Expects a list of ARNs: ["arn:aws:s3:::my-dr-bucket", "arn:aws:s3:::my-archive"]
authorized_destinations := input.parameters.authorized_replication_destinations

# Helper: Check if a destination is authorized
is_authorized_destination(dest_bucket_arn) {
    # Iterate over the authorized list
    authorized_destinations[_] == dest_bucket_arn
}

# Helper: Find Unauthorized Rules
# Returns any rule where the destination bucket is NOT in the allowlist
unauthorized_rules[rule_id] {
    rule := replication_rules[_]
    
    # Extract destination bucket
    dest_arn := rule.destination.bucket
    
    # Check authorization
    not is_authorized_destination(dest_arn)
    
    # Return rule ID for metadata/debugging
    rule_id := rule.id
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "pass" {
    # If replication is NOT enabled, there is no incorrect configuration to flag.
    # (Whether replication *should* be enabled is S3.C87's job).
    not has_replication
} else := "fail" {
    # Fail if we find any rule pointing to an unauthorized bucket
    count(unauthorized_rules) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Replication rules target unauthorized destinations. Rules: %v", [unauthorized_rules]) {
    result == "fail"
} else := "All replication rules target authorized destination buckets."

expectedConfiguration := "Replication destination buckets must be explicitly listed in 'authorized_replication_destinations'."