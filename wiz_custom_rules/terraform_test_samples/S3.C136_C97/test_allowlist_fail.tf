# S3.C97 (inventory_destination_check) - allowlist - VIOLATING

# Inventory reports sent to an unauthorized bucket: 1 finding
resource "aws_s3_bucket_inventory" "rogue_destination" {
  bucket                   = "inventoried-bucket"
  name                     = "exfil-inventory"
  included_object_versions = "All"

  schedule {
    frequency = "Daily"
  }

  destination {
    bucket {
      bucket_arn = "arn:aws:s3:::rogue-inventory-bucket"
      format     = "CSV"
    }
  }
}
