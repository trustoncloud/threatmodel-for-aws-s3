# Remediation

The bucket in the finding has ABAC (tag-based access control) on although not authorized for it, or off although authorized. Turn ABAC off, or on (`Status=Enabled`) for a bucket in `authorized_abac_buckets`:

```bash
aws s3api get-bucket-abac --bucket <bucket-name>
aws s3api put-bucket-abac --bucket <bucket-name> --abac-status Status=Disabled
```

Before enabling ABAC, review policies that use tag conditions; once it is on, `PutBucketTagging` stops working, so manage tags with `TagResource` and `UntagResource`. If the bucket is approved for ABAC, add its name to `authorized_abac_buckets` and enable ABAC. Wiz does not collect ABAC status, so only the Terraform source is checked and a change made outside it is not detected. Replace `<bucket-name>` with the bucket in the finding.

## References

- [aws s3api get-bucket-abac](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-abac.html)
- [aws s3api put-bucket-abac](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-abac.html)
- [Enabling ABAC in general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging-enable-abac.html)
- [Using tags with S3 general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
1) Enable ABAC on an unauthorized general purpose bucket, or 2) disable ABAC on an authorized general purpose bucket; it should be detected.
