Give the bucket a policy with this Deny, whose only condition is `StringNotEquals` on `s3:DataAccessPointArn`, with no `not_principals`, `not_actions` or `not_resources`. In place of `<access-point-arn>`, list only access point ARNs in `authorized_access_points`, or add an approved access point there. The bucket's `policy` argument and each `aws_s3_bucket_policy` attached to it are read; a bucket with neither fails. Only one of them applies after apply, so when a bucket sets more than one, each must hold the full Deny.

```hcl
resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = data.aws_iam_policy_document.example.json
}

data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.example.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["<access-point-arn>"]
    }
  }
}
```

A policy written as JSON, with `jsonencode` or a heredoc, is read the same way.

## References

- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
