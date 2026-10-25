# S3.C172 (bucket_abac_configuration) - allowlist - COMPLIANT

# Authorized bucket with ABAC enabled, bucket named by reference
resource "aws_s3_bucket" "authorized" {
  bucket = "authorized-abac-bucket"
}

resource "aws_s3_bucket_abac" "authorized" {
  bucket = aws_s3_bucket.authorized.bucket

  abac_status {
    status = "Enabled"
  }
}

# Authorized bucket with ABAC enabled, bucket named by literal
resource "aws_s3_bucket" "reports" {
  bucket = "authorized-abac-reports"
}

resource "aws_s3_bucket_abac" "reports" {
  bucket = "authorized-abac-reports"

  abac_status {
    status = "Enabled"
  }
}

# Ordinary bucket with no ABAC resource: ABAC stays off
resource "aws_s3_bucket" "ordinary" {
  bucket = "example-ordinary-bucket"
}

# Ordinary bucket with ABAC explicitly disabled
resource "aws_s3_bucket" "disabled" {
  bucket = "example-abac-disabled-bucket"
}

resource "aws_s3_bucket_abac" "disabled" {
  bucket = aws_s3_bucket.disabled.id

  abac_status {
    status = "Disabled"
  }
}
