Give each bucket a policy with this Deny, which blocks every service-linked role on the bucket and its objects. The bucket's `policy` argument and each `aws_s3_bucket_policy` attached to it are read as JSON, `jsonencode` or an `aws_iam_policy_document` data source in the same module. Only one of them applies after apply, so when a bucket sets more than one, each must hold the full Deny. Exempt only roles in `authorized_service_roles`.

```hcl
resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyServiceLinkedRoles"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.example.arn, "${aws_s3_bucket.example.arn}/*"]
      Condition = {
        ArnLike = {
          "aws:PrincipalArn" = "arn:aws:iam::*:role/aws-service-role/*"
        }
        ArnNotEquals = {
          "aws:PrincipalArn" = ["arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"]
        }
      }
    }]
  })
}
```

Write the pattern as a literal string with `*` for the account: a pattern built from a reference such as `data.aws_partition` is known only at apply and is reported.

## References

- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
