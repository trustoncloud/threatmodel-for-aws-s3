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

# Same-account access point: the owner account is stated in account_id
resource "aws_s3_access_point" "same_account" {
  bucket     = "authorized-bucket"
  name       = "same-account-ap"
  account_id = "123456789012"
}

# Access point targeting the bucket through its bucket attribute. A second
# bucket whose resource name starts the same way is not authorized and is
# not the one referenced
resource "aws_s3_bucket" "authorized_data_archive" {
  bucket = "rogue-archive-bucket"
}

resource "aws_s3_access_point" "by_bucket_attribute" {
  bucket            = aws_s3_bucket.authorized_data.bucket
  name              = "by-bucket-attribute-ap"
  bucket_account_id = "123456789012"
}

# Access point targeting a bucket read through a data source
data "aws_s3_bucket" "shared" {
  bucket = "authorized-bucket"
}

resource "aws_s3_access_point" "by_data_source" {
  bucket            = data.aws_s3_bucket.shared.id
  name              = "by-data-source-ap"
  bucket_account_id = "123456789012"
}
