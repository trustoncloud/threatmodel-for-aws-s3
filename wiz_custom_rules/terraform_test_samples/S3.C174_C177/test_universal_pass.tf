# S3.C177 (account_regional_namespace) - universal - COMPLIANT

# Bucket created in its account regional namespace
resource "aws_s3_bucket" "regional" {
  bucket           = "example-logs-123456789012-us-east-1-an"
  bucket_namespace = "account-regional"
}

# Namespace set from a variable: not judged statically
variable "bucket_namespace" {
  type    = string
  default = "account-regional"
}

resource "aws_s3_bucket" "fromvar" {
  bucket           = "example-data-123456789012-us-east-1-an"
  bucket_namespace = var.bucket_namespace
}

# Bucket in Bahrain, where S3 offers no account regional namespace: not judged
resource "aws_s3_bucket" "bahrain" {
  bucket = "example-bahrain-bucket"
  region = "me-south-1"
}

variable "example_region" {
  type    = string
  default = "me-south-1"
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
