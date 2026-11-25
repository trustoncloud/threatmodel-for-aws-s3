# Remediation

The bucket in the finding has no bucket policy statement that limits object access to authorized access points, or its statement lets in an unauthorized access point. Add this Deny:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideAuthorizedAccessPoints",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::<bucket-name>/*",
      "Condition": {
        "StringNotEquals": {
          "s3:DataAccessPointArn": ["arn:aws:s3:<region>:<account-id>:accesspoint/<access-point-name>"]
        }
      }
    }
  ]
}
```

`put-bucket-policy` replaces the whole policy, so merge the statement into the current one, saved as `policy.json`:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

The Deny also blocks direct object requests to the bucket, and S3 features that access points do not support, such as Cross-Region Replication, so check what uses the bucket first. A Deny with another condition, or written with `NotPrincipal`, `NotAction` or `NotResource`, does not count. If a listed access point is approved, add its ARN to `authorized_access_points` instead. Replace `<bucket-name>` with the bucket in the finding, and `<region>`, `<account-id>` and `<access-point-name>` with each authorized access point.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Configuring IAM policies for using access points](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-policies.html)
- [Bucket policies for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove/modify the deny on the bucket policy; it should be detected.
