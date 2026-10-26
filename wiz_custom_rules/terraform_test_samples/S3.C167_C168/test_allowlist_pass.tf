# S3.C168 (ssec_conditional_blocking) - allowlist - COMPLIANT (0 findings)

# Ordinary bucket blocking SSE-C through its default encryption setting
resource "aws_s3_bucket" "ordsetting" {
  bucket = "ordsetting-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ordsetting" {
  bucket = aws_s3_bucket.ordsetting.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    blocked_encryption_types = ["SSE-C"]
  }
}

# Required bucket explicitly allowing SSE-C
resource "aws_s3_bucket" "ssec_required" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ssec_required" {
  bucket = aws_s3_bucket.ssec_required.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    blocked_encryption_types = ["NONE"]
  }
}

# Bucket with a required path (mixed-bucket/secure/) explicitly allowing SSE-C
resource "aws_s3_bucket" "mixedok" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mixedok" {
  bucket = aws_s3_bucket.mixedok.id

  rule {
    blocked_encryption_types = ["NONE"]
  }
}
