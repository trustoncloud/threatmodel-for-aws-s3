# S3.C100 (bucket_vpc_restriction) - allowlist - VIOLATING

# No VPC restriction (no policy): 1 finding
resource "aws_s3_bucket" "no_restriction" {
  bucket = "no-restriction-bucket"
}

# Restriction allows an unauthorized VPC: 1 finding
resource "aws_s3_bucket" "rogue_vpc" {
  bucket = "rogue-vpc-bucket"
}

resource "aws_s3_bucket_policy" "rogue_vpc" {
  bucket = aws_s3_bucket.rogue_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptVpc",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::rogue-vpc-bucket", "arn:aws:s3:::rogue-vpc-bucket/*"],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-99999999999999999" }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, restriction allows an unauthorized VPC: 1 finding
resource "aws_s3_bucket" "ds_unauth_vpc" {
  bucket = "rogue-vpc-ds-bucket"
}

data "aws_iam_policy_document" "ds_unauth_vpc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::rogue-vpc-ds-bucket", "arn:aws:s3:::rogue-vpc-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-88888888888888888"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_unauth_vpc" {
  bucket = aws_s3_bucket.ds_unauth_vpc.id
  policy = data.aws_iam_policy_document.ds_unauth_vpc.json
}

# Restriction applies to one role only: 1 finding
resource "aws_s3_bucket" "vpc_onerole" {
  bucket = "vpc-onerole-bucket"
}

resource "aws_s3_bucket_policy" "vpc_onerole" {
  bucket = aws_s3_bucket.vpc_onerole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vpc-onerole-bucket", "arn:aws:s3:::vpc-onerole-bucket/*"],
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Restriction covers a single action only: 1 finding
resource "aws_s3_bucket" "vpc_getonly" {
  bucket = "vpc-getonly-bucket"
}

resource "aws_s3_bucket_policy" "vpc_getonly" {
  bucket = aws_s3_bucket.vpc_getonly.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": ["arn:aws:s3:::vpc-getonly-bucket", "arn:aws:s3:::vpc-getonly-bucket/*"],
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Restriction reaches the objects only, bucket-level requests stay open: 1 finding
resource "aws_s3_bucket" "vpc_objonly" {
  bucket = "vpc-objonly-bucket"
}

resource "aws_s3_bucket_policy" "vpc_objonly" {
  bucket = aws_s3_bucket.vpc_objonly.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.vpc_objonly.arn}/*",
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Second key under the same operator widens access (either match is enough): 1 finding
resource "aws_s3_bucket" "vpc_extrakey" {
  bucket = "vpc-extrakey-bucket"
}

resource "aws_s3_bucket_policy" "vpc_extrakey" {
  bucket = aws_s3_bucket.vpc_extrakey.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vpc-extrakey-bucket", "arn:aws:s3:::vpc-extrakey-bucket/*"],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpc": "vpc-0123456789abcdef0",
          "aws:SourceVpce": "vpce-0123456789abcdef0"
        }
      }
    }
  ]
}
POLICY
}
