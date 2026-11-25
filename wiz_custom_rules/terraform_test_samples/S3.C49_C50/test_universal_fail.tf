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

# One flag written as the string Terraform converts to false: 1 finding
resource "aws_s3_account_public_access_block" "quoted_false" {
  block_public_acls       = "true"
  block_public_policy     = "1"
  ignore_public_acls      = "true"
  restrict_public_buckets = "0"
}

# One flag false on a block created through count: 1 finding
resource "aws_s3_account_public_access_block" "count_one" {
  count = 1

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = true
}
