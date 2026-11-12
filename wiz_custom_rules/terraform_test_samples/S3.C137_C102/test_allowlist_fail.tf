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

# An approved distribution listed beside one that is not: 1 finding
resource "aws_s3_bucket" "mixed_oac" {
  bucket = "mixed-oac-bucket"
}

resource "aws_s3_bucket_policy" "mixed_oac" {
  bucket = aws_s3_bucket.mixed_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::mixed-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": [
            "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345",
            "arn:aws:cloudfront::123456789012:distribution/E9ROGUE9999999"
          ]
        }
      }
    }
  ]
}
POLICY
}

# A distribution ID that only starts with the approved ID: 1 finding
resource "aws_s3_bucket" "lookalike_oac" {
  bucket = "lookalike-oac-bucket"
}

resource "aws_s3_bucket_policy" "lookalike_oac" {
  bucket = aws_s3_bucket.lookalike_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::lookalike-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345X"
        }
      }
    }
  ]
}
POLICY
}

# A negated test admits every distribution but the approved one: 1 finding
resource "aws_s3_bucket" "negated_oac" {
  bucket = "negated-oac-bucket"
}

resource "aws_s3_bucket_policy" "negated_oac" {
  bucket = aws_s3_bucket.negated_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::negated-oac-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"
        }
      }
    }
  ]
}
POLICY
}

# A wildcard value is never approved: 1 finding
resource "aws_s3_bucket" "wildcard_oac" {
  bucket = "wildcard-oac-bucket"
}

resource "aws_s3_bucket_policy" "wildcard_oac" {
  bucket = aws_s3_bucket.wildcard_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::wildcard-oac-bucket/*",
      "Condition": {
        "ArnLike": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED*"
        }
      }
    }
  ]
}
POLICY
}

# The CloudFront service with no aws:SourceArn test: 1 finding
resource "aws_s3_bucket" "nocond_oac" {
  bucket = "nocond-oac-bucket"
}

resource "aws_s3_bucket_policy" "nocond_oac" {
  bucket = aws_s3_bucket.nocond_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::nocond-oac-bucket/*"
    }
  ]
}
POLICY
}

# An approved identity listed beside one that is not: 1 finding
resource "aws_s3_bucket" "mixed_oai" {
  bucket = "mixed-oai-bucket"
}

resource "aws_s3_bucket_policy" "mixed_oai" {
  bucket = aws_s3_bucket.mixed_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2AUTHORIZED12345",
          "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2AUTHORIZED12345X"
        ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::mixed-oai-bucket/*"
    }
  ]
}
POLICY
}

# An identity created in the same configuration is not resolved by this source scan, so it
# cannot be approved: 1 finding
resource "aws_cloudfront_origin_access_identity" "legacy" {
  comment = "legacy identity"
}

resource "aws_s3_bucket" "created_oai" {
  bucket = "created-oai-bucket"
}

resource "aws_s3_bucket_policy" "created_oai" {
  bucket = aws_s3_bucket.created_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "${aws_cloudfront_origin_access_identity.legacy.iam_arn}" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::created-oai-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy form, an approved distribution beside one that is not,
# under an implicit Allow: 1 finding
resource "aws_s3_bucket" "ds_mixed_cf" {
  bucket = "ds-mixed-cf-bucket"
}

data "aws_iam_policy_document" "ds_mixed_cf" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-mixed-cf-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345",
        "arn:aws:cloudfront::123456789012:distribution/E7ROGUEDS7777777",
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_mixed_cf" {
  bucket = aws_s3_bucket.ds_mixed_cf.id
  policy = data.aws_iam_policy_document.ds_mixed_cf.json
}

# Data-source policy form, a negated test on the approved distribution: 1 finding
resource "aws_s3_bucket" "ds_negated_cf" {
  bucket = "ds-negated-cf-bucket"
}

data "aws_iam_policy_document" "ds_negated_cf" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-negated-cf-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_negated_cf" {
  bucket = aws_s3_bucket.ds_negated_cf.id
  policy = data.aws_iam_policy_document.ds_negated_cf.json
}
