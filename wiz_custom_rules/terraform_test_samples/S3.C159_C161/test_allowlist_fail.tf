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
