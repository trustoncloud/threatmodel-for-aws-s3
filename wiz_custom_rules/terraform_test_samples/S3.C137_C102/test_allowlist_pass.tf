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

# Legacy OAI association to an authorized identity, beside a principal that is
# not CloudFront
resource "aws_s3_bucket" "cf_oai" {
  bucket = "cf-oai-bucket"
}

resource "aws_s3_bucket_policy" "cf_oai" {
  bucket = aws_s3_bucket.cf_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2AUTHORIZED12345",
          "arn:aws:iam::123456789012:role/app"
        ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cf-oai-bucket/*"
    }
  ]
}
POLICY
}

# OAC association written with ArnLike and no wildcard, with a second test
# that only narrows the grant
resource "aws_s3_bucket" "cf_arnlike" {
  bucket = "cf-arnlike-bucket"
}

resource "aws_s3_bucket_policy" "cf_arnlike" {
  bucket = aws_s3_bucket.cf_arnlike.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cf-arnlike-bucket/*",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"
        },
        "StringEquals": { "aws:SourceAccount": "123456789012" }
      }
    }
  ]
}
POLICY
}

# A role whose name mentions CloudFront is not an origin access identity
resource "aws_s3_bucket" "deployer" {
  bucket = "deployer-bucket"
}

resource "aws_s3_bucket_policy" "deployer" {
  bucket = aws_s3_bucket.deployer.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/cloudfront-deployer" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::deployer-bucket/*"
    }
  ]
}
POLICY
}

# A policy takes its statements from the data source it names, never from one
# whose name it only starts with: cfdoc grants an unapproved distribution and
# is attached to no bucket
resource "aws_s3_bucket" "cf_named" {
  bucket = "cf-named-bucket"
}

data "aws_iam_policy_document" "cfdoc" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::some-other-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E9ROGUE9999999"]
    }
  }
}

data "aws_iam_policy_document" "cfdoc_main" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::cf-named-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }
}

resource "aws_s3_bucket_policy" "cf_named" {
  bucket = aws_s3_bucket.cf_named.id
  policy = data.aws_iam_policy_document.cfdoc_main.json
}
