Point the access point at a bucket in `authorized_buckets` and state the bucket's owner account as a literal 12-digit ID in `bucket_account_id` (or in `account_id` when the access point and the bucket share an account), using an account in `authorized_accounts`. An access point that states neither argument, or gives the account or bucket name by a value the source scan cannot resolve (such as `data.aws_caller_identity`), is reported.

```hcl
resource "aws_s3_access_point" "example" {
  bucket            = "authorized-bucket"
  bucket_account_id = "123456789012"
}
```

## References

- [aws_s3_access_point (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_access_point)

Checked 2026-11-18 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
