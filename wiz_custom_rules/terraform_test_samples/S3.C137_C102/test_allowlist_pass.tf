# S3.C102 (cloudfront_association_check) - allowlist - COMPLIANT (0 findings)

# OAC association to an authorized distribution
resource "aws_s3_bucket" "cf_oac" {
  bucket = "cf-oac-bucket"
}

resource "aws_s3_bucket_policy" "cf_oac" {
  bucket = aws_s3_bucket.cf_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontOac",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cf-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"
        }
      }
    }
  ]
}
POLICY
}

# Bucket with no CloudFront association at all
resource "aws_s3_bucket" "plain" {
  bucket = "plain-bucket"
}

resource "aws_s3_bucket_policy" "plain" {
  bucket = aws_s3_bucket.plain.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowApp",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/app" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::plain-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy form, OAC to an authorized distribution: no finding
resource "aws_s3_bucket" "cf_ds" {
  bucket = "cf-ds-bucket"
}

data "aws_iam_policy_document" "cf_ds" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::cf-ds-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }
}

resource "aws_s3_bucket_policy" "cf_ds" {
  bucket = aws_s3_bucket.cf_ds.id
  policy = data.aws_iam_policy_document.cf_ds.json
}
