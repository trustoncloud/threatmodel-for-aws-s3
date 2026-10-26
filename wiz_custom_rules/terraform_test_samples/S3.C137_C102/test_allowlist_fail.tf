# S3.C102 (cloudfront_association_check) - allowlist - VIOLATING

# OAC association to an unauthorized distribution: 1 finding
resource "aws_s3_bucket" "rogue_oac" {
  bucket = "rogue-oac-bucket"
}

resource "aws_s3_bucket_policy" "rogue_oac" {
  bucket = aws_s3_bucket.rogue_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontOac",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E9ROGUE9999999"
        }
      }
    }
  ]
}
POLICY
}

# Legacy OAI association to an unauthorized identity: 1 finding
resource "aws_s3_bucket" "rogue_oai" {
  bucket = "rogue-oai-bucket"
}

resource "aws_s3_bucket_policy" "rogue_oai" {
  bucket = aws_s3_bucket.rogue_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontOai",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E9ROGUE9999999"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-oai-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy form, OAC to an unauthorized distribution: 1 finding
resource "aws_s3_bucket" "rogue_cf_ds" {
  bucket = "rogue-cf-ds-bucket"
}

data "aws_iam_policy_document" "rogue_cf_ds" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::rogue-cf-ds-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E8ROGUEDS8888888"]
    }
  }
}

resource "aws_s3_bucket_policy" "rogue_cf_ds" {
  bucket = aws_s3_bucket.rogue_cf_ds.id
  policy = data.aws_iam_policy_document.rogue_cf_ds.json
}
