# Remediation

The bucket in the finding blocks SSE-C although listed as requiring it, or allows SSE-C although not listed. Set `BlockedEncryptionTypes` in its default encryption to `SSE-C`, or `NONE` for a listed bucket. `put-bucket-encryption` replaces the whole setting, so keep the current `ApplyServerSideEncryptionByDefault` and `BucketKeyEnabled` values in place of the SSE-S3 default shown:

```bash
aws s3api get-bucket-encryption --bucket <bucket-name>
aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BlockedEncryptionTypes":{"EncryptionType":["SSE-C"]}}]}'
```

Blocking SSE-C rejects new SSE-C uploads and replicated SSE-C objects, so first check that no workload still writes with SSE-C; existing SSE-C objects stay readable. If the bucket is approved for SSE-C, add its name to `buckets_requiring_ssec`, the list S3.C147 also uses. A path entry (`bucket/prefix/`) allows SSE-C on its whole bucket. Replace `<bucket-name>` with the bucket in the finding.

## References

- [aws s3api get-bucket-encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-encryption.html)
- [aws s3api put-bucket-encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-encryption.html)
- [Blocking or unblocking SSE-C for a general purpose bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html)
- [Using server-side encryption with customer-provided keys (SSE-C)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
1) Block SSE-C on a bucket requiring SSE-C, or 2) remove the block on SSE-C on a bucket not requiring SSE-C; it should be detected.
