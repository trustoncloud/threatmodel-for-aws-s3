# S3.C177 (account_regional_namespace) - universal - VIOLATING

# No bucket_namespace, so the bucket lands in the global namespace: 1 finding
resource "aws_s3_bucket" "unset" {
  bucket = "example-global-bucket"
}

# Namespace set to global explicitly: 1 finding
resource "aws_s3_bucket" "global" {
  bucket           = "example-explicit-global-bucket"
  bucket_namespace = "global"
}

# Generated name, no bucket_namespace: 1 finding
resource "aws_s3_bucket" "prefixed" {
  bucket_prefix = "example-prefixed-"
}

# Bucket created through count with no bucket_namespace: 1 finding
resource "aws_s3_bucket" "count_one" {
  count  = 1
  bucket = "example-counted-global-bucket"
}
