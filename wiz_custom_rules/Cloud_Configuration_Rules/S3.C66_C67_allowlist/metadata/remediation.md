# Remediation

The policy of the bucket in the finding does not deny uploads that use a KMS key outside `authorized_kms_key_ids`. Add this Deny:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthorizedKmsKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<bucket-name>/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:<region>:<account-id>:key/<key-id>"
        }
      }
    }
  ]
}
```

`put-bucket-policy` replaces the whole policy, so merge the statement into the current one, saved as `policy.json`, or use the document above if the bucket has none:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

Keep the key test as the only condition, without `NotPrincipal`, `NotAction` or `NotResource`, and list keys as full ARNs. Uploads must then use an authorized key, in the request or as the bucket's default encryption key. If the bucket must accept another key, add its ARN to `authorized_kms_key_ids` once approved. Replace `<bucket-name>` with the bucket in the finding, and `<region>`, `<account-id>` and `<key-id>` with those of an authorized key.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Using server-side encryption with AWS KMS keys (SSE-KMS)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
- [Examples of Amazon S3 bucket policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create a bucket not blocking PutObject requests with an unauthorized KMS key; it should be detected.
