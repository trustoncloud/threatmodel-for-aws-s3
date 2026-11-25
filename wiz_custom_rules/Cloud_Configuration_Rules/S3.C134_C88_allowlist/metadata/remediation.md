# Remediation

An enabled replication rule on the bucket in the finding does not match its route in `authorized_replications`: its destination, replica KMS key, replica ownership or Replication Time Control differs. Rewrite the rule to match; `put-bucket-replication` replaces the whole configuration, so keep every rule the bucket needs:

```bash
aws s3api get-bucket-replication --bucket <bucket-name>
aws s3api put-bucket-replication --bucket <bucket-name> --replication-configuration '{
  "Role": "<role-arn>",
  "Rules": [{
    "ID": "<rule-id>",
    "Priority": 1,
    "Status": "Enabled",
    "Filter": {},
    "DeleteMarkerReplication": {"Status": "Disabled"},
    "SourceSelectionCriteria": {"SseKmsEncryptedObjects": {"Status": "Enabled"}},
    "Destination": {
      "Bucket": "<destination-bucket-arn>",
      "EncryptionConfiguration": {"ReplicaKmsKeyID": "<replica-key-arn>"},
      "ReplicationTime": {"Status": "Enabled", "Time": {"Minutes": 15}},
      "Metrics": {"Status": "Enabled", "EventThreshold": {"Minutes": 15}}
    }
  }]
}'
```

The example fits a route with a replica key and Replication Time Control. Without a replica key, leave out `SourceSelectionCriteria` and `EncryptionConfiguration`; where the route passes replica ownership, add `"AccessControlTranslation": {"Owner": "Destination"}` and `Account` (the destination account ID) to `Destination`. If the change was approved, update the route in `authorized_replications` instead, and the same list in S3.C87. Replace `<bucket-name>` with the bucket in the finding, `<role-arn>` and `<rule-id>` with its current values, and `<destination-bucket-arn>` and `<replica-key-arn>` with the route's ARNs.

## References

- [aws s3api get-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-replication.html)
- [aws s3api put-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-replication.html)
- [Replication configuration file elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-add-config.html)
- [Replicating encrypted objects (SSE-S3, SSE-KMS, DSSE-KMS, SSE-C)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-config-for-kms-objects.html)
- [Changing the replica owner](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-change-owner.html)
- [Meeting compliance requirements with S3 Replication Time Control](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-time-control.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Modify the configuration of an authorized replication; it should be detected.
