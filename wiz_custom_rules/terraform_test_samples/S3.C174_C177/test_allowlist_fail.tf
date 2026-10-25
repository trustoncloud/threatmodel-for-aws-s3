# S3.C177 (account_regional_namespace) - allowlist - VIOLATING

# Unauthorized bucket with no bucket_namespace: 1 finding
resource "aws_s3_bucket" "unset" {
  bucket = "example-global-bucket"
}

# Unauthorized bucket set to the global namespace explicitly: 1 finding
resource "aws_s3_bucket" "global" {
  bucket           = "example-explicit-global-bucket"
  bucket_namespace = "global"
}

# Generated name, which no authorized entry can match: 1 finding
resource "aws_s3_bucket" "prefixed" {
  bucket_prefix = "example-legacy-"
}
