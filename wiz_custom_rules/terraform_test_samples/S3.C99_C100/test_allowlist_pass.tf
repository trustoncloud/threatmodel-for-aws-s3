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
