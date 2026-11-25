Give each bucket an `aws_s3_bucket_policy` holding both Deny statements, written as JSON (`jsonencode` or a heredoc) or in a `data "aws_iam_policy_document"` block named in `policy`. The bucket's own `policy` argument is read too, but the provider deprecates it in favor of `aws_s3_bucket_policy`. Each of them writes the whole bucket policy and only one holds after apply, so a bucket that sets more than one needs both Denies in each.

```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}

resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.example.arn, "${aws_s3_bucket.example.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyOldTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.example.arn, "${aws_s3_bucket.example.arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
    ]
  })
}
```

A bucket with no bucket policy is reported. A statement with `NotPrincipal`, `NotAction` or `NotResource`, or with an extra condition key other than `aws:PrincipalIsAWSService` set to `false` under `BoolIfExists`, does not count.

## References

- [aws_s3_bucket (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket)
- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
