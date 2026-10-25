# S3.C161 (cross_account_ap_check) - allowlist - COMPLIANT (0 findings)

# Cross-account access point: authorized bucket owned by an authorized account
resource "aws_s3_access_point" "finance" {
  bucket            = "authorized-bucket"
  name              = "finance-ap"
  bucket_account_id = "123456789012"
}

# Access point targeting the bucket by reference; the resolved bucket name is
# authorized
resource "aws_s3_bucket" "authorized_data" {
  bucket = "authorized-bucket"
}

resource "aws_s3_access_point" "by_reference" {
  bucket            = aws_s3_bucket.authorized_data.id
  name              = "by-reference-ap"
  bucket_account_id = "123456789012"
}
