Name only buckets in `authorized_buckets`, and their objects, in each Allow of the S3 endpoint's policy, or add a bucket ARN to `authorized_buckets` once approved. Write each name in full, or reference an `aws_s3_bucket` in the same configuration with a literal `bucket`. An Allow with `NotResource` or no resource is reported.

```hcl
resource "aws_vpc_endpoint" "example" {
  service_name = "com.amazonaws.<region>.s3"
  policy       = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<bucket-name>", "arn:aws:s3:::<bucket-name>/*"]}
  ]
}
POLICY
}
```

The policy goes in `policy` or an attached `aws_vpc_endpoint_policy`, as JSON or from an `aws_iam_policy_document`; an endpoint with neither keeps the full-access default and is reported.

## References

- [aws_vpc_endpoint (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/vpc_endpoint)

Checked 2026-11-18 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
