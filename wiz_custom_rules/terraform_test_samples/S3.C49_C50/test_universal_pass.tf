# S3.C50 (account_public_access_block) - universal - COMPLIANT (0 findings)

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
