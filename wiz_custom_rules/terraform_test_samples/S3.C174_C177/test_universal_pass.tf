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
