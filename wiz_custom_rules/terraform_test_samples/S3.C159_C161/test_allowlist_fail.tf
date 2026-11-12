# S3.C161 (cross_account_ap_check) - allowlist - VIOLATING

# Unauthorized bucket: 1 finding
resource "aws_s3_access_point" "rogue_bkt_ap" {
  bucket            = "rogue-bucket"
  name              = "rogue-bkt-ap"
  bucket_account_id = "123456789012"
}

# Authorized bucket owned by an unauthorized account: 1 finding
resource "aws_s3_access_point" "bad_acct_ap" {
  bucket            = "authorized-bucket"
  name              = "bad-acct-ap"
  bucket_account_id = "999999999999"
}

# Bucket not in the authorized set (name is not an exact match): 1 finding
resource "aws_s3_access_point" "superset_name_ap" {
  bucket            = "authorized-bucket-backup"
  name              = "superset-name-ap"
  bucket_account_id = "123456789012"
}

# Reference to a bucket whose resource name only starts with the name of an
# authorized one: 1 finding
resource "aws_s3_bucket" "main" {
  bucket = "authorized-bucket"
}

resource "aws_s3_bucket" "main_backup" {
  bucket = "rogue-backup-bucket"
}

resource "aws_s3_access_point" "lookalike_ref_ap" {
  bucket            = aws_s3_bucket.main_backup.id
  name              = "lookalike-ref-ap"
  bucket_account_id = "123456789012"
}

# Authorized bucket, with no account stated on the access point: 1 finding
resource "aws_s3_access_point" "no_account_ap" {
  bucket = "authorized-bucket"
  name   = "no-account-ap"
}

# Reference to a bucket with a generated name, so the name is not in the
# source. The resource name is never taken for the bucket name: 1 finding
resource "aws_s3_bucket" "authorized-bucket" {
  bucket_prefix = "generated-"
}

resource "aws_s3_access_point" "generated_name_ap" {
  bucket            = aws_s3_bucket.authorized-bucket.id
  name              = "generated-name-ap"
  bucket_account_id = "123456789012"
}

# Owner account given by a variable, so it is not in the source: 1 finding
variable "owner_account" {
  type = string
}

resource "aws_s3_access_point" "variable_account_ap" {
  bucket            = "authorized-bucket"
  name              = "variable-account-ap"
  bucket_account_id = var.owner_account
}

# Same-account access point in an account one digit away from an authorized
# one: 1 finding
resource "aws_s3_access_point" "near_account_ap" {
  bucket     = "authorized-bucket"
  name       = "near-account-ap"
  account_id = "123456789013"
}
