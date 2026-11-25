# S3.C50 (account_public_access_block) - universal - COMPLIANT (0 findings)

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Flags written as the strings Terraform converts to true
resource "aws_s3_account_public_access_block" "quoted" {
  block_public_acls       = "true"
  block_public_policy     = "1"
  ignore_public_acls      = "true"
  restrict_public_buckets = "1"
}

variable "example_block_public_access" {
  type    = bool
  default = true
}

# Values given by reference resolve at apply time; the cloud matcher judges them.
resource "aws_s3_account_public_access_block" "by_reference" {
  block_public_acls       = var.example_block_public_access
  block_public_policy     = var.example_block_public_access
  ignore_public_acls      = var.example_block_public_access
  restrict_public_buckets = var.example_block_public_access
}

# Never created (a literal count of 0): not judged, though every flag is off
resource "aws_s3_account_public_access_block" "count_zero" {
  count = 0

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
