In each bucket's policy, grant access only to principals in `authorized_principals`. The bucket's `policy` argument and each `aws_s3_bucket_policy` attached to it are read together. Identifiers of Allow statements with principal type `AWS` or `*` are compared as written, so use the literal ARN: a reference to a role or user is known only at apply and is reported. Type `CanonicalUser` is compared with `authorized_canonical_users`, which is empty by default. A statement with no `effect` counts as Allow. An Allow written with `NotPrincipal` (`not_principals` in the data source) grants every principal except those it lists, so it cannot be shown to stay within the authorized list and is reported whatever it lists. A scan reads a `not_principals` statement as one that names no principal, so an Allow that names no principal is reported too. Name the authorized principals in `principals` instead.

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
      type        = "AWS"
      identifiers = ["arn:aws:iam::<account-id>:role/<role-name>"]
    }
  }
}
```

A policy written as JSON, with `jsonencode` or a heredoc, is read the same way.

## References

- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
