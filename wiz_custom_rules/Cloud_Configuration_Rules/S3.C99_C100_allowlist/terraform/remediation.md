Attach an `aws_s3_bucket_policy` to the bucket with this Deny, whose only condition is `StringNotEquals` on `aws:SourceVpc`. In place of `<vpc-id>`, list only VPC IDs in `authorized_vpcs`, or add an approved VPC there. The deprecated `policy` argument of `aws_s3_bucket` is read too. Only one bucket policy applies after apply, so a bucket that sets more than one (the argument and an `aws_s3_bucket_policy`, or several of them) fails unless each holds the full Deny, and an unauthorized VPC in any of them is reported. A statement with `not_principals`, `not_actions` or `not_resources` does not count.

```hcl
resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = data.aws_iam_policy_document.example.json
}

data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.example.arn, "${aws_s3_bucket.example.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["<vpc-id>"]
    }
  }
}
```

A policy written as JSON, with `jsonencode` or a heredoc, is read the same way.

## References

- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
