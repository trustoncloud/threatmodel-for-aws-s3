# S3.C147 (bucket_enforce_ssec) - allowlist - VIOLATING

# Required bucket with a policy that does not enforce SSE-C: 1 finding
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
      "Sid": "AllowRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*"
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/ but the deny covers another path: 1 finding
resource "aws_s3_bucket" "mixedfail" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixedfail" {
  bucket = aws_s3_bucket.mixedfail.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/tmp/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Whole-bucket entry enforced for one role only: 1 finding
resource "aws_s3_bucket" "ssecrole" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecrole" {
  bucket = aws_s3_bucket.ssecrole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Whole-bucket entry narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "ssecextra" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecextra" {
  bucket = aws_s3_bucket.ssecextra.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}
