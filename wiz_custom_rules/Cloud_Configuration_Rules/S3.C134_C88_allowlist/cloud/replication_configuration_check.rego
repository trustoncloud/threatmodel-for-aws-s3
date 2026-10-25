package wiz

# --- Configuration ---
# Authorized replication routes: source bucket name, then each destination
# bucket ARN it may replicate to and that route's expected settings:
#   replica_kms_key  KMS key ARN for replicas of SSE-KMS objects, or null when
#                    the route must not name a replica key
#   owner_override   whether replica ownership passes to the destination account
#   rtc              whether S3 Replication Time Control must be enabled
# S3.C87 checks which buckets may replicate. Keep in sync with S3.C87.
authorized_replications := {
    "authorized-source-bucket": {
        "arn:aws:s3:::authorized-replica-bucket": {
            "replica_kms_key": "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key",
            "owner_override": false,
            "rtc": true,
        },
        "arn:aws:s3:::authorized-archive-bucket": {
            "replica_kms_key": null,
            "owner_override": false,
            "rtc": false,
        },
    },
}

# --- Logic ---
default result := "pass"

# Replication arrives at bucketReplication.ReplicationConfiguration; the whole
# aggregation is null when the bucket has no replication.
fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketReplication.result == "Success"
}

routes := authorized_replications[input.Name]

enabled_rules[rule] {
    rule := input.bucketReplication.ReplicationConfiguration.Rules[_]
    rule.Status == "Enabled"
}

rule_label(rule) := sprintf("rule '%s'", [rule.ID]) {
    is_string(rule.ID)
    rule.ID != ""
} else := "a rule"

setting(route, key, fallback) := object.get(route, key, fallback)

replica_key(rule) := k {
    k := rule.Destination.EncryptionConfiguration.ReplicaKmsKeyID
    is_string(k)
    k != ""
}

replica_key_is(rule, expected) {
    replica_key(rule) == expected
}

replica_key_label(rule) := k {
    k := replica_key(rule)
} else := "no key"

kms_objects_replicated(rule) {
    rule.SourceSelectionCriteria.SseKmsEncryptedObjects.Status == "Enabled"
}

owner_overridden(rule) {
    rule.Destination.AccessControlTranslation.Owner == "Destination"
}

rtc_enabled(rule) {
    rule.Destination.ReplicationTime.Status == "Enabled"
    rule.Destination.Metrics.Status == "Enabled"
}

# Target: every enabled rule replicates to a destination authorized for this
# source bucket.
problems[msg] {
    rule := enabled_rules[_]
    not routes[rule.Destination.Bucket]
    msg := sprintf("%s replicates to unauthorized destination %s", [rule_label(rule), rule.Destination.Bucket])
}

# Encryption: a route with a replica key replicates SSE-KMS objects with
# exactly that key; a route without one names no replica key.
problems[msg] {
    rule := enabled_rules[_]
    route := routes[rule.Destination.Bucket]
    setting(route, "replica_kms_key", null) != null
    not kms_objects_replicated(rule)
    msg := sprintf("%s does not replicate SSE-KMS objects (SourceSelectionCriteria.SseKmsEncryptedObjects)", [rule_label(rule)])
}

problems[msg] {
    rule := enabled_rules[_]
    route := routes[rule.Destination.Bucket]
    expected := setting(route, "replica_kms_key", null)
    expected != null
    not replica_key_is(rule, expected)
    msg := sprintf("%s encrypts replicas with %v instead of %s", [rule_label(rule), replica_key_label(rule), expected])
}

problems[msg] {
    rule := enabled_rules[_]
    route := routes[rule.Destination.Bucket]
    setting(route, "replica_kms_key", null) == null
    key := replica_key(rule)
    msg := sprintf("%s encrypts replicas with %s but the route expects no replica key", [rule_label(rule), key])
}

# Ownership: the replica owner override matches the route.
problems[msg] {
    rule := enabled_rules[_]
    route := routes[rule.Destination.Bucket]
    setting(route, "owner_override", false) == true
    not owner_overridden(rule)
    msg := sprintf("%s does not pass replica ownership to the destination account", [rule_label(rule)])
}

problems[msg] {
    rule := enabled_rules[_]
    route := routes[rule.Destination.Bucket]
    setting(route, "owner_override", false) == false
    owner_overridden(rule)
    msg := sprintf("%s passes replica ownership to the destination account, which the route does not expect", [rule_label(rule)])
}

# RTC: a route that requires Replication Time Control has it and its metrics on.
problems[msg] {
    rule := enabled_rules[_]
    route := routes[rule.Destination.Bucket]
    setting(route, "rtc", false) == true
    not rtc_enabled(rule)
    msg := sprintf("%s does not enable Replication Time Control with metrics", [rule_label(rule)])
}

# Buckets not on the list are S3.C87's finding, not this rule's.
result := "skip" {
    not fetch_ok
} else := "skip" {
    input.bucketReplication == null
} else := "skip" {
    not routes
} else := "fail" {
    count(problems) > 0
}

# --- Metadata ---
currentConfiguration := concat("; ", sort([p | p := problems[_]])) {
    result == "fail"
} else := "Every enabled replication rule matches its authorized route."

expectedConfiguration := "Each enabled replication rule of an authorized bucket must target an authorized destination for that bucket, with the route's replica KMS key (and SSE-KMS objects replicated), replica ownership and Replication Time Control settings."
