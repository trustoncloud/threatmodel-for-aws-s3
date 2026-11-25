# Remediation

A replication rule of the bucket in the finding has no replication metrics. Add `"Metrics": {"Status": "Enabled"}` to the `Destination` of every rule; `put-bucket-replication` replaces the whole configuration, so send every rule back with its other settings unchanged:

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
    "Destination": {
      "Bucket": "arn:aws:s3:::<destination-bucket>",
      "Metrics": {"Status": "Enabled"}
    }
  }]
}'
```

S3 publishes the metrics to CloudWatch, where they are billed as custom metrics. Replace `<bucket-name>` with the source bucket in the finding, and the other markers with the values its current configuration holds.

## References

- [aws s3api get-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-replication.html)
- [aws s3api put-bucket-replication](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-replication.html)
- [Using S3 Replication metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/repl-metrics.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Modify the replication metric of an authorized replication; it should be detected.
