For each bucket or path in `buckets_requiring_ssec`, attach an `aws_s3_bucket_policy` with this Deny. Its only condition is the `StringNotEquals` test shown, or `Null` `true` on the same key. For a path, use `"${aws_s3_bucket.example.arn}/<path>/*"` as the resource. The bucket is matched to the list by its `bucket` argument. The deprecated `policy` argument of `aws_s3_bucket` is read too. Only one bucket policy applies after apply, so a bucket that sets more than one (the argument and an `aws_s3_bucket_policy`, or several of them) is reported unless each holds the Deny. A statement with `not_principals`, `not_actions` or `not_resources` does not count.

```hcl
resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = data.aws_iam_policy_document.example.json
}

data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.example.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["AES256"]
    }
  }
}
```

A policy written as JSON, with `jsonencode` or a heredoc, is read the same way.

## References

- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
