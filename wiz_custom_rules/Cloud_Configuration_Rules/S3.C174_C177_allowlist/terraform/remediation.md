Set `bucket_namespace = "account-regional"` and a name ending in `-<account-id>-<region>-an`, or add the bucket name to `authorized_global_buckets` until it is replaced. An unset `bucket_namespace` means the global namespace and is reported. The namespace is fixed at creation, so declare a new bucket; stop writes to the old one (replication included), finish and check the copy, and move clients before you remove it, with its `force_destroy` off so Terraform refuses to delete objects still in it. A bucket whose `region` is me-south-1 or me-central-1 is not checked (the provider's region is not read), and a name or `region` given by reference is not judged. `bucket_namespace` needs hashicorp/aws provider 6.x.

```hcl
resource "aws_s3_bucket" "example" {
  bucket           = "<prefix>-<account-id>-<region>-an"
  bucket_namespace = "account-regional"
}
```

## References

- [aws_s3_bucket (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket)

Checked 2026-11-18 against hashicorp/aws 6.70.0: resources, arguments and links.
