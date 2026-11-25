# Remediation

The bucket in the finding, or a path in it, must use SSE-C, but the bucket policy does not deny uploads there without it. Add this Deny, whose `StringNotEquals` test also matches uploads with no SSE-C algorithm header:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUploadsWithoutSseC",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<bucket-name>/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-customer-algorithm": "AES256"
        }
      }
    }
  ]
}
```

For a required path, set `Resource` to `arn:aws:s3:::<bucket-name>/<path>/*`. `put-bucket-policy` replaces the whole policy, so merge the statement into the current one, saved as `policy.json`:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

If the bucket's default encryption blocks SSE-C, unblock it. A Deny with another condition, or with `NotPrincipal`, `NotAction` or `NotResource`, does not count. If the bucket or path no longer needs SSE-C, remove its entry from `buckets_requiring_ssec` instead. Replace `<bucket-name>` with the bucket in the finding and `<path>` with the required path.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Using server-side encryption with customer-provided keys (SSE-C)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html)
- [Blocking or unblocking SSE-C for a general purpose bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html)
- [IAM JSON policy elements: Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create a bucket requiring SSE-C, not blocking PutObject requests with unauthorized encryption; it should be detected.
