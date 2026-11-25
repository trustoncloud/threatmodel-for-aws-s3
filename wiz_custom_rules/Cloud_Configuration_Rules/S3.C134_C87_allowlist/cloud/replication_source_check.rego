package wiz

# --- Configuration ---
# Authorized replication routes: source bucket name, then each destination
# bucket ARN and its expected settings. This rule reads only the source names.
# Keep in sync with S3.C88.
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

# bucketReplication is null when the bucket has no replication.
fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketReplication.result == "Success"
}

replication_enabled {
    input.bucketReplication.ReplicationConfiguration.Rules[_].Status == "Enabled"
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    replication_enabled
    not authorized_replications[input.Name]
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket '%s' has replication enabled but is not authorized to replicate.", [input.Name]) {
    result == "fail"
} else := "Bucket is authorized to replicate, or has no replication enabled."

expectedConfiguration := sprintf("Only authorized buckets may have replication enabled: %v", [sort([b | authorized_replications[b]])])
