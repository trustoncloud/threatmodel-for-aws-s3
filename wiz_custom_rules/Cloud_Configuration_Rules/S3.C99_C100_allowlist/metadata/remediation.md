# Remediation

The bucket in the finding has no bucket policy statement that limits access to authorized VPCs, or its statement lets in an unauthorized VPC. Add this Deny:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideAuthorizedVpcs",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::<bucket-name>",
        "arn:aws:s3:::<bucket-name>/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpc": ["<vpc-id>"]
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

The Deny blocks every request from outside the listed VPCs, console requests and policy changes included. If it locks everyone out, the account root user can still delete the policy. A statement using `aws:SourceVpce`, another condition, `NotPrincipal`, `NotAction` or `NotResource` does not count. If a listed VPC is approved, add its ID to `authorized_vpcs` instead. Replace `<bucket-name>` with the bucket in the finding and `<vpc-id>` with each authorized VPC ID.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Controlling access from VPC endpoints with bucket policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies-vpc-endpoint.html)
- [Bucket policies for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the control limiting access to only authorized VPC(s); it should be detected.
