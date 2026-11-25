# Remediation

The bucket in the finding replicates with an IAM role that is not authorized. No command changes the role alone, and `put-bucket-replication` replaces the whole configuration, so set `Role` to an authorized role and keep the bucket's own `Rules` from the first command in place of the example shown:

```bash
aws s3api get-bucket-replication --bucket <bucket-name> --query ReplicationConfiguration
aws s3api put-bucket-replication --bucket <bucket-name> --replication-configuration '{
  "Role": "<role-arn>",
  "Rules": [{
    "ID": "<rule-id>",
    "Priority": 1,
    "Status": "Enabled",
    "Filter": {},
    "DeleteMarkerReplication": {"Status": "Disabled"},
    "Destination": {"Bucket": "<destination-bucket-arn>"}
  }]
}'
```

The new role needs the permissions replication uses on the source and destination buckets. If the current role is approved for this bucket, add its ARN under the bucket's name in `authorized_replication_roles` instead; a role listed only for another bucket does not count. Replace `<bucket-name>` with the bucket in the finding and `<role-arn>` with an authorized role ARN.

## References

- [aws s3api get-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-replication.html)
- [aws s3api put-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-replication.html)
- [Setting up permissions for live replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html)
- [Replication configuration file elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-add-config.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create/modify a replication with an unauthorized IAM role; it should be detected.
