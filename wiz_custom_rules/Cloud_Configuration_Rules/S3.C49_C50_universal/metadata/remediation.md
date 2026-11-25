# Remediation

Account-level S3 Block Public Access is off, or not all four of its settings are on, in the account that owns the bucket in the finding. Turn on all four settings for the account:

```bash
aws s3control put-public-access-block --account-id <account-id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

The settings apply to every bucket and access point in the account, so first check that no bucket must stay public, such as one that hosts a public website. The check runs on each bucket, so every bucket in the account carries the same finding, and an account with no buckets is not checked. Replace `<account-id>` with the account that owns the bucket in the finding.

## References

- [aws s3control put-public-access-block](https://docs.aws.amazon.com/cli/latest/reference/s3control/put-public-access-block.html)
- [Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Configuring block public access settings for your account](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-account.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the account-level S3 Block Public Access of an AWS account; it should be detected.
