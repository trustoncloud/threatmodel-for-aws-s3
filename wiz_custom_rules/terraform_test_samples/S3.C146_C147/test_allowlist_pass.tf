# S3.C147 (bucket_enforce_ssec) - allowlist - COMPLIANT (0 findings)

# Required bucket enforcing SSE-C on PutObject
resource "aws_s3_bucket" "ssec_required" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssec_required" {
  bucket = aws_s3_bucket.ssec_required.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyMissingSsecHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Ordinary bucket: out of scope for this control
resource "aws_s3_bucket" "ordinary" {
  bucket = "ordinary-bucket"
}

# Path entry mixed-bucket/secure/ enforced on that path, via a reference
resource "aws_s3_bucket" "mixedpass" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixedpass" {
  bucket = aws_s3_bucket.mixedpass.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.mixedpass.arn}/secure/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}
