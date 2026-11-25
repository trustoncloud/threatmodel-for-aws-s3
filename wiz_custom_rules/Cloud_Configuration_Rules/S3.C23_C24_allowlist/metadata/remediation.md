# Remediation

The S3 VPC endpoint in the finding can reach buckets outside `authorized_buckets`; the default full-access policy fails too. Make every Allow name only authorized buckets and their objects, without `NotResource`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAuthorizedBuckets",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::<bucket-name>",
        "arn:aws:s3:::<bucket-name>/*"
      ]
    }
  ]
}
```

`modify-vpc-endpoint` replaces the whole policy, so fix the Allow statements in the current one and save it as `policy.json`:

```bash
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <vpce-id> --query "VpcEndpoints[0].PolicyDocument" --output text
aws ec2 modify-vpc-endpoint --vpc-endpoint-id <vpce-id> --policy-document file://policy.json
```

Write bucket names in full, without wildcards. To allow another bucket, such as an AWS-owned one used by AWS services or package repositories, list it in the Allow and add its ARN (`arn:aws:s3:::<bucket-name>`) to `authorized_buckets` once approved. S3 traffic through a NAT gateway or any other route is not covered. Replace `<vpce-id>` with the endpoint in the finding and `<bucket-name>` with each authorized bucket.

## References

- [aws ec2 describe-vpc-endpoints](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html)
- [aws ec2 modify-vpc-endpoint](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-vpc-endpoint.html)
- [Gateway endpoints for Amazon S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)
- [Control access to VPC endpoints using endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the control limiting access to only authorized S3 bucket(s); it should be detected.
