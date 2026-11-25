# S3.C100 (bucket_vpc_restriction) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "vpc_restricted" {
  bucket = "vpc-restricted-bucket"
}

resource "aws_s3_bucket_policy" "vpc_restricted" {
  bucket = aws_s3_bucket.vpc_restricted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAuthorizedVpc",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::vpc-restricted-bucket",
        "arn:aws:s3:::vpc-restricted-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, authorized VPC: no finding
resource "aws_s3_bucket" "vpc_ds" {
  bucket = "vpc-ds-bucket"
}

data "aws_iam_policy_document" "vpc_ds" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::vpc-ds-bucket", "arn:aws:s3:::vpc-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket_policy" "vpc_ds" {
  bucket = aws_s3_bucket.vpc_ds.id
  policy = data.aws_iam_policy_document.vpc_ds.json
}

# Resources given as references to the bucket ARN, AWS wildcard principal
resource "aws_s3_bucket" "vpcref" {
  bucket = "vpcref-bucket"
}

resource "aws_s3_bucket_policy" "vpcref" {
  bucket = aws_s3_bucket.vpcref.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAuthorizedVpc",
      "Effect": "Deny",
      "Principal": { "AWS": "*" },
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.vpcref.arn}", "${aws_s3_bucket.vpcref.arn}/*"],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# A wildcard reaches a bucket whose name holds dots
resource "aws_s3_bucket" "vpc_dotted" {
  bucket = "logs.example.com"
}

resource "aws_s3_bucket_policy" "vpc_dotted" {
  bucket = aws_s3_bucket.vpc_dotted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Restriction set in the policy argument of the bucket, action with an
# upper-case service prefix
resource "aws_s3_bucket" "inline_vpc" {
  bucket = "inline-vpc-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "S3:*",
      "Resource": [
        "arn:aws:s3:::inline-vpc-bucket",
        "arn:aws:s3:::inline-vpc-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Policy argument of the bucket built by a data source
resource "aws_s3_bucket" "inline_vpc_ds" {
  bucket = "inline-vpc-ds-bucket"
  policy = data.aws_iam_policy_document.inline_vpc_ds.json
}

data "aws_iam_policy_document" "inline_vpc_ds" {
  statement {
    effect    = "Deny"
    actions   = ["S3:*"]
    resources = ["arn:aws:s3:::inline-vpc-ds-bucket", "arn:aws:s3:::inline-vpc-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
    }
  }
}

# Both forms: only one applies after apply, so each holds the full
# restriction; the policy argument splits it over two statements
resource "aws_s3_bucket" "both_vpc" {
  bucket = "both-vpc-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::both-vpc-bucket",
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::both-vpc-bucket/*",
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_vpc" {
  bucket = aws_s3_bucket.both_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::both-vpc-bucket",
        "arn:aws:s3:::both-vpc-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# --- Never-created resources and statements the source does not show ---

# A bucket that is never created (count = 0, or for_each over an empty
# collection) is not judged, even with no bucket policy.
resource "aws_s3_bucket" "zzncsubj" {
  count  = 0
  bucket = "zz-vpc-bucket"
}

resource "aws_s3_bucket" "zzfesubj" {
  for_each = toset([])
  bucket = "zz-vpc-bucket"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "zz-vpc-bucket"
}

data "aws_iam_policy_document" "zz_src_extra" {
  statement {
    sid       = "ReadObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "zz_src_added" {
  source_policy_documents = [data.aws_iam_policy_document.zz_src_extra.json]

  statement {
    sid       = "OnlyAuthorizedVpc"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}
