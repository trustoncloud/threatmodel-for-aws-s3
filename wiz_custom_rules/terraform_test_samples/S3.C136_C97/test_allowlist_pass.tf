# S3.C97 (inventory_destination_check) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket_inventory" "authorized_destination" {
  bucket                   = "inventoried-bucket"
  name                     = "weekly-inventory"
  included_object_versions = "All"

  schedule {
    frequency = "Weekly"
  }

  destination {
    bucket {
      bucket_arn = "arn:aws:s3:::authorized-inventory-bucket"
      format     = "CSV"
      account_id = "123456789012"
    }
  }
}
