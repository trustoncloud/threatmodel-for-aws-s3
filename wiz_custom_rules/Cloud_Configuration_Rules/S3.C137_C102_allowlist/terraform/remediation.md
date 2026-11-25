In the `aws_s3_bucket_policy` of each bucket, and in the deprecated `policy` argument of `aws_s3_bucket`, which is read too, grant CloudFront access only to IDs in `authorized_cloudfront_ids`: an origin access identity, or the `cloudfront.amazonaws.com` service limited to a distribution by an `aws:SourceArn` test (`StringEquals`, `ArnEquals` or `ArnLike`, no wildcard). Write each ARN as a literal: a reference to an `aws_cloudfront_distribution` or `aws_cloudfront_origin_access_identity` is known only at apply and is reported.

```hcl
resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = data.aws_iam_policy_document.example.json
}

data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.example.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::<account-id>:distribution/<distribution-id>"]
    }
  }
}
```

A policy written as JSON, with `jsonencode` or a heredoc, is read the same way.

## References

- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
