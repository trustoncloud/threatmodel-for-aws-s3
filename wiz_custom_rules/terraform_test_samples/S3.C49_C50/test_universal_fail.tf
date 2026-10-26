# S3.C50 (account_public_access_block) - universal - VIOLATING

# One flag explicitly false: 1 finding
resource "aws_s3_account_public_access_block" "one_false" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = false
}

# Three flags omitted (provider default false): 3 findings
resource "aws_s3_account_public_access_block" "mostly_omitted" {
  block_public_acls = true
}
