# S3.C172 (bucket_abac_configuration) - allowlist - VIOLATING

# ABAC enabled on a bucket not authorized for it: 1 finding
resource "aws_s3_bucket" "unauthorized" {
  bucket = "example-unauthorized-abac-bucket"
}

resource "aws_s3_bucket_abac" "unauthorized" {
  bucket = aws_s3_bucket.unauthorized.id

  abac_status {
    status = "Enabled"
  }
}

# ABAC disabled on an authorized bucket: 1 finding
resource "aws_s3_bucket" "authorized" {
  bucket = "authorized-abac-bucket"
}

resource "aws_s3_bucket_abac" "authorized" {
  bucket = aws_s3_bucket.authorized.bucket

  abac_status {
    status = "Disabled"
  }
}

# Authorized bucket with no aws_s3_bucket_abac, so ABAC is off: 1 finding
resource "aws_s3_bucket" "reports" {
  bucket = "authorized-abac-reports"
}
