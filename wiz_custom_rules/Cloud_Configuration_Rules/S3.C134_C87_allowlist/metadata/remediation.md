# Remediation

The bucket in the finding has replication turned on but is not authorized to replicate. Remove its replication configuration:

```bash
aws s3api get-bucket-replication --bucket <bucket-name>
aws s3api delete-bucket-replication --bucket <bucket-name>
```

The check fails only on an enabled rule, so setting every rule's `Status` to `Disabled` with `put-bucket-replication` also clears the finding. If the bucket is approved to replicate, add its name to `authorized_replications` in the rule's configuration instead, with each destination bucket ARN it may replicate to and that route's settings. S3.C88 holds the same list and checks each route, so update both. Replace `<bucket-name>` with the bucket in the finding.

## References

- [aws s3api get-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-replication.html)
- [aws s3api delete-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-bucket-replication.html)
- [Replicating objects within and across Regions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html)
- [Replication configuration file elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-add-config.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Configure replication on an unauthorized bucket; it should be detected.
