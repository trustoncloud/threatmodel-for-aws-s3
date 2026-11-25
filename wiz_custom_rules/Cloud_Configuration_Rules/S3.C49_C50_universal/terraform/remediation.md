Set all four flags to `true` on the account's `aws_s3_account_public_access_block`. Each defaults to `false`, so an omitted flag is reported:

```hcl
resource "aws_s3_account_public_access_block" "example" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
```

A configuration with no `aws_s3_account_public_access_block` is not checked here; the cloud check covers the account.

## References

- [aws_s3_account_public_access_block (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_account_public_access_block)

Checked 2026-11-18 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
