# S3.C177 (account_regional_namespace) - allowlist - COMPLIANT

# Bucket created in its account regional namespace
resource "aws_s3_bucket" "regional" {
  bucket           = "example-logs-123456789012-us-east-1-an"
  bucket_namespace = "account-regional"
}

# Global bucket authorized to stay until it is replaced
resource "aws_s3_bucket" "legacy" {
  bucket = "example-legacy-bucket-awaiting-migration"
}

# Bucket in Bahrain, where S3 offers no account regional namespace: not judged
resource "aws_s3_bucket" "bahrain" {
  bucket = "example-bahrain-bucket"
  region = "me-south-1"
}
