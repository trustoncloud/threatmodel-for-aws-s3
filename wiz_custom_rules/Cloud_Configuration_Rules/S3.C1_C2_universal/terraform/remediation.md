Attach SCPs to the organization root that hold both Deny statements between them, each on all S3 actions and every S3 resource (`*` or `arn:aws:s3:*`) with no other condition than an optional `aws:PrincipalIsAWSService` set to `false` (under `Bool` or `BoolIfExists`, since an SCP governs only signed requests, which always carry that key); `arn:aws:s3:::*` does not count, since it misses requests through access points. Build the content with `jsonencode`, a heredoc or an `aws_iam_policy_document` in the same module. Point `target_id` at the root with a literal `r-` ID or `roots[0].id` of an `aws_organizations_organization` resource or data source, the same way for every attachment, since each spelling counts as its own root; an attachment whose target or content comes from a variable is reported.

```hcl
data "aws_organizations_organization" "current" {}

resource "aws_organizations_policy" "example" {
  name = "deny-insecure-s3"
  type = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyS3WithoutTls"
        Effect    = "Deny"
        Action    = "s3:*"
        Resource  = "*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyS3TlsBelow12"
        Effect    = "Deny"
        Action    = "s3:*"
        Resource  = "*"
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
    ]
  })
}

resource "aws_organizations_policy_attachment" "example" {
  policy_id = aws_organizations_policy.example.id
  target_id = data.aws_organizations_organization.current.roots[0].id
}
```

SCPs attached to an OU or an account are not judged, and a scan with no root attachment and no `aws_organizations_organization` resource gives no result.

## References

- [aws_organizations_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/organizations_policy)
- [aws_organizations_policy_attachment (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/organizations_policy_attachment)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
