Add two Deny statements to the S3 endpoint's policy, one when `aws:SecureTransport` is false and one when `s3:TlsVersion` is below 1.2, each on every principal, S3 action and resource with no other condition than an optional `aws:PrincipalIsAWSService` set to `false` under `BoolIfExists`. The policy goes in `policy` or an attached `aws_vpc_endpoint_policy`, as JSON or from an `aws_iam_policy_document`; an endpoint with neither keeps the full-access default and is reported.

```hcl
resource "aws_vpc_endpoint" "example" {
  service_name = "com.amazonaws.<region>.s3"
  policy       = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
     "Condition": {"NumericLessThan": {"s3:TlsVersion": "1.2"}}}
  ]
}
POLICY
}
```

Both are needed: plain HTTP requests carry no TLS version and pass the TLS test.

## References

- [aws_vpc_endpoint (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/vpc_endpoint)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
