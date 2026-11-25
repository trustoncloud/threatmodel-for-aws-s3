# Remediation

The bucket in the finding is listed in `worm_buckets` but does not have Object Lock enabled with its listed default retention. Enable versioning, which Object Lock needs, then set the default retention. The last command also enables Object Lock on an existing bucket:

```bash
aws s3api get-object-lock-configuration --bucket <bucket-name>
aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled
aws s3api put-object-lock-configuration --bucket <bucket-name> --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}'
```

Use the bucket's listed `mode` in place of `COMPLIANCE`, and its `min_days` or more in place of `365`; `Years` may replace `Days`, and a year counts 365 days. Once enabled, Object Lock cannot be turned off and versioning cannot be suspended, and objects stored in COMPLIANCE mode cannot be deleted by anyone until their retention ends.

The default applies to object versions written after the change. Objects already stored keep their own retention: an S3 Inventory report with the Object Lock fields lists it, and S3 Batch Operations can set it. If the bucket does not require WORM, remove it from `worm_buckets`; if its current default is approved, change its entry. Replace `<bucket-name>` with the bucket in the finding.

## References

- [aws s3api get-object-lock-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-lock-configuration.html)
- [aws s3api put-bucket-versioning](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-versioning.html)
- [aws s3api put-object-lock-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object-lock-configuration.html)
- [Locking objects with Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Configuring S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html)
- [Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create a bucket requiring WORM 1) without S3 Object Lock or 2) with an incorrect default S3 Object Lock; it should be detected.
