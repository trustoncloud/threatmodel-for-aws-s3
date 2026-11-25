# Remediation

The policy of the bucket in the finding allows an IAM principal outside the approved list. Remove each unauthorized principal from every Allow statement, and drop a statement left with none. An Allow written with `NotPrincipal` grants every principal except those it lists, so it cannot be shown to stay within the approved list and is reported whatever it lists: rewrite it with a `Principal` that names the approved principals. An Allow for an approved principal looks like this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowApprovedRole",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account-id>:role/<role-name>" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::<bucket-name>/*"
    }
  ]
}
```

`put-bucket-policy` replaces the whole policy, so edit the current one, saved as `policy.json`:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

If no statement is left, delete the policy with `aws s3api delete-bucket-policy --bucket <bucket-name>`. If the principal is approved, add its ARN, as the policy writes it, to `authorized_principals` instead. Conditions are not read, so an Allow for every principal (`"*"`) fails even when a condition narrows it. An Allow for a canonical user ID (`"CanonicalUser"`) fails unless the ID is in `authorized_canonical_users`, which is empty by default. Service principals are not checked. Replace `<bucket-name>` with the bucket in the finding, and `<account-id>` and `<role-name>` with an approved principal.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [aws s3api delete-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-bucket-policy.html)
- [Bucket policies for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [AWS JSON policy elements: Principal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Allow an unauthorized IAM principal on a bucket policy; it should be detected.
