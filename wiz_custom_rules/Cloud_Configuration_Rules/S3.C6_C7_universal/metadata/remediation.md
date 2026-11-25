# Remediation

The bucket in the finding has no bucket policy statement that denies requests sent without TLS, or none that denies TLS versions older than 1.2. Add both Deny statements:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<bucket-name>", "arn:aws:s3:::<bucket-name>/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<bucket-name>", "arn:aws:s3:::<bucket-name>/*"],
      "Condition": {"NumericLessThan": {"s3:TlsVersion": "1.2"}}
    }
  ]
}
```

`put-bucket-policy` replaces the whole policy, so merge both statements into the current one, saved as `policy.json`, or use the document above if the bucket has none:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

Each Deny counts only when it covers every principal, every S3 action, the bucket and every object in it, with no `NotPrincipal`, `NotAction` or `NotResource`. Its transport test may sit beside `"aws:PrincipalIsAWSService": "false"` under `BoolIfExists`, which exempts AWS services calling on your behalf and still denies anonymous requests, since they omit that key. Under plain `Bool` the exemption does not count, and nothing else may sit beside the test. `BoolIfExists` and `NumericLessThanIfExists` also count. The check reads the bucket policy only, so a resource control policy that enforces the same Denies still leaves a finding. Replace `<bucket-name>` with the bucket in the finding.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Bucket policy examples using condition keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html)
- [Security best practices for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the statement on a bucket policy 1) denying all unencrypted requests and 2) denying unauthorized TLS versions; it should be detected.
