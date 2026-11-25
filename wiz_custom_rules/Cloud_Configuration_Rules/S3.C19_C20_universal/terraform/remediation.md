Add a Deny to the S3 endpoint's policy that refuses callers outside your organization. The policy goes in `policy` or an attached `aws_vpc_endpoint_policy`, as JSON or from an `aws_iam_policy_document`; an endpoint with neither keeps the full-access default and is reported.

```hcl
resource "aws_vpc_endpoint" "example" {
  service_name = "com.amazonaws.<region>.s3"
  policy       = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
     "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "<org-id>"}}}
  ]
}
POLICY
}
```

Keep the Deny as broad as shown, with the organization test as its only condition. `aws:PrincipalAccount` with `StringNotEquals`, or `aws:PrincipalOrgPaths` with `ForAllValues:StringNotLike`, also counts.

## References

- [aws_vpc_endpoint (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/vpc_endpoint)

Checked 2026-11-18 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
