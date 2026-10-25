# S3.C67 (bucket_enforce_kms_key) - allowlist - VIOLATING

# Bucket with no bucket policy: 1 finding
resource "aws_s3_bucket" "no_policy" {
  bucket = "no-policy-bucket"
}

# Bucket whose deny permits an unauthorized KMS key: 1 finding
resource "aws_s3_bucket" "rogue_key" {
  bucket = "rogue-key-bucket"
}

resource "aws_s3_bucket_policy" "rogue_key" {
  bucket = aws_s3_bucket.rogue_key.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthorizedKmsKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::rogue-key-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:999999999999:key/rogue-key"
        }
      }
    }
  ]
}
POLICY
}

# Key enforcement applies to one role only: 1 finding
resource "aws_s3_bucket" "key_onerole" {
  bucket = "key-onerole-bucket"
}

resource "aws_s3_bucket_policy" "key_onerole" {
  bucket = aws_s3_bucket.key_onerole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-onerole-bucket/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    }
  ]
}
POLICY
}

# Key enforcement reaches one prefix only: 1 finding
resource "aws_s3_bucket" "key_prefix" {
  bucket = "key-prefix-bucket"
}

resource "aws_s3_bucket_policy" "key_prefix" {
  bucket = aws_s3_bucket.key_prefix.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-prefix-bucket/uploads/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    }
  ]
}
POLICY
}

# Key enforcement narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "key_extracond" {
  bucket = "key-extracond-bucket"
}

resource "aws_s3_bucket_policy" "key_extracond" {
  bucket = aws_s3_bucket.key_extracond.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-extracond-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}
