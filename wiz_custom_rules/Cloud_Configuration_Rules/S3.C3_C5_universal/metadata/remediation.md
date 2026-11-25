# Remediation

The S3 VPC endpoint in the finding does not deny requests without TLS, or with TLS below 1.2. Add both Deny statements to its policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyTlsBelow12",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": {
          "s3:TlsVersion": "1.2"
        }
      }
    }
  ]
}
```

The full-access Allow stands in for your own Allow statements. `modify-vpc-endpoint` replaces the whole policy, so merge both Deny statements into the current one, saved as `policy.json`:

```bash
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <vpce-id> --query "VpcEndpoints[0].PolicyDocument" --output text
aws ec2 modify-vpc-endpoint --vpc-endpoint-id <vpce-id> --policy-document file://policy.json
```

Both are needed: a plain HTTP request carries no TLS version, so it passes the TLS test. Keep each Deny as broad as shown, with no `NotPrincipal`, `NotAction` or `NotResource` element. Its transport test may sit beside `"aws:PrincipalIsAWSService": "false"` under `BoolIfExists`, which exempts AWS services calling on your behalf and still denies anonymous requests, since they omit that key. Under plain `Bool` the exemption does not count, and nothing else may sit beside the test. `BoolIfExists`, `NumericLessThanIfExists` and a TLS floor above 1.2 also count. Replace `<vpce-id>` with the endpoint in the finding.

## References

- [aws ec2 describe-vpc-endpoints](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html)
- [aws ec2 modify-vpc-endpoint](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-vpc-endpoint.html)
- [Control access to VPC endpoints using endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)
- [Bucket policy examples using condition keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html)
- [Security best practices for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create/remove the statement on a VPC endpoint policy denying 1) all unencrypted requests or 2) unauthorized TLS version(s); it should be detected.
