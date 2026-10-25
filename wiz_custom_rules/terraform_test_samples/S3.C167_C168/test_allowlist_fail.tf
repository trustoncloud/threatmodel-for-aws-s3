# S3.C168 (ssec_conditional_blocking) - allowlist - VIOLATING

# Required bucket whose default encryption setting blocks SSE-C: 1 finding
resource "aws_s3_bucket" "ssecset" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ssecset" {
  bucket = aws_s3_bucket.ssecset.id

  rule {
    blocked_encryption_types = ["SSE-C"]
  }
}

# Required bucket that does not set blocked_encryption_types: 1 finding
resource "aws_s3_bucket" "ssecmissing" {
  bucket = "ssec-required-bucket"
}

# Ordinary bucket with no SSE-C block at all: 1 finding
resource "aws_s3_bucket" "ordinary" {
  bucket = "ordinary-bucket"
}

# Ordinary bucket explicitly allowing SSE-C: 1 finding
resource "aws_s3_bucket" "ordnone" {
  bucket = "ordnone-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ordnone" {
  bucket = aws_s3_bucket.ordnone.id

  rule {
    blocked_encryption_types = ["NONE"]
  }
}

# Ordinary bucket blocking SSE-C only through its bucket policy: 1 finding
resource "aws_s3_bucket" "ordpolicy" {
  bucket = "ordpolicy-bucket"
}

resource "aws_s3_bucket_policy" "ordpolicy" {
  bucket = aws_s3_bucket.ordpolicy.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ordpolicy-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "false" }
      }
    }
  ]
}
POLICY
}

# Bucket with a required path whose setting blocks SSE-C bucket-wide: 1 finding
resource "aws_s3_bucket" "mixedbad" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mixedbad" {
  bucket = aws_s3_bucket.mixedbad.id

  rule {
    blocked_encryption_types = ["SSE-C"]
  }
}
