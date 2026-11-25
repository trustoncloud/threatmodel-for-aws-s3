# S3.C177 (account_regional_namespace) - allowlist - COMPLIANT

# Bucket created in its account regional namespace
resource "aws_s3_bucket" "regional" {
  bucket           = "example-logs-123456789012-us-east-1-an"
  bucket_namespace = "account-regional"
}

# Global bucket authorized to stay until it is replaced
resource "aws_s3_bucket" "legacy" {
  bucket = "example-legacy-bucket-awaiting-migration"
}

# Bucket in Bahrain, where S3 offers no account regional namespace: not judged
resource "aws_s3_bucket" "bahrain" {
  bucket = "example-bahrain-bucket"
  region = "me-south-1"
}

variable "example_bucket_name" {
  type    = string
  default = "example-legacy-bucket-awaiting-migration"
}

variable "example_region" {
  type    = string
  default = "me-south-1"
}

# Values given by reference resolve at apply time; the cloud matcher judges them.
# The name may be an authorized global bucket.
resource "aws_s3_bucket" "name_by_reference" {
  bucket = var.example_bucket_name
}

# Values given by reference resolve at apply time; the cloud matcher judges them.
# The region may be one with no account regional namespace.
resource "aws_s3_bucket" "region_by_reference" {
  bucket = "example-region-by-reference-bucket"
  region = var.example_region
}

# Never created (a literal count of 0): not judged, though bucket_namespace is
# not set
resource "aws_s3_bucket" "count_zero" {
  count  = 0
  bucket = "example-never-created-bucket"
}
