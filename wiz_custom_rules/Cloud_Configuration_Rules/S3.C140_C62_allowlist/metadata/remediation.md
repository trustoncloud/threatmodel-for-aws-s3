# Remediation

The default encryption of the bucket in the finding does not use a KMS key authorized for it: it is SSE-S3, the AWS managed key `aws/s3`, a key alias, or a key outside `authorized_kms_key_ids` (or outside the bucket's own entry in `authorized_kms_key_ids_by_bucket`). Set SSE-KMS with an authorized key ARN. `put-bucket-encryption` replaces the whole setting, so keep the bucket's current `BucketKeyEnabled` and `BlockedEncryptionTypes` values from the first command in place of those shown:

```bash
aws s3api get-bucket-encryption --bucket <bucket-name>
aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:<region>:<account-id>:key/<key-id>"},"BucketKeyEnabled":true,"BlockedEncryptionTypes":{"EncryptionType":["SSE-C"]}}]}'
```

Name the key by its ARN: an alias resolves in the account that uploads. The key must be in the bucket's Region, and its key policy must let the uploaders use it.

The default covers new objects uploaded without a key. Objects already stored keep their encryption, and an upload can name another key, so the bucket settings cannot show that every object uses an authorized key. Deny uploads with other keys in the bucket policy (S3.C67), find objects stored without SSE-KMS with an S3 Inventory report that includes the encryption status, check an object's key with `head-object` (`SSEKMSKeyId`), and re-encrypt objects with S3 Batch Operations:

```bash
aws s3api head-object --bucket <bucket-name> --key <object-key>
```

If the current key is approved for this bucket, add its ARN to `authorized_kms_key_ids`, or under the bucket's name in `authorized_kms_key_ids_by_bucket` for a key of its own. If the bucket must keep SSE-S3 because what writes to it cannot use a KMS key, such as a server access log destination, add its name to `sse_s3_buckets` once approved. Replace `<bucket-name>` with the bucket in the finding, `<object-key>` with an object in it, and `<region>`, `<account-id>` and `<key-id>` with those of an authorized key.

## References

- [aws s3api get-bucket-encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-encryption.html)
- [aws s3api put-bucket-encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-encryption.html)
- [aws s3api head-object](https://docs.aws.amazon.com/cli/latest/reference/s3api/head-object.html)
- [Setting default server-side encryption behavior for Amazon S3 buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html)
- [Cataloging and analyzing your data with S3 Inventory](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html)
- [Copy objects with S3 Batch Operations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-copy-object.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Upload encrypted data 1) using an unauthorized KMS key, or 2) using SSE-S3; it should be detected.
