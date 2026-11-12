# S3.C110 (access_point_restriction) - allowlist - VIOLATING

# No access point restriction (no policy): 1 finding
resource "aws_s3_bucket" "no_restriction" {
  bucket = "no-restriction-bucket"
}

# Restriction allows an unauthorized access point: 1 finding
resource "aws_s3_bucket" "rogue_ap" {
  bucket = "rogue-ap-bucket"
}

resource "aws_s3_bucket_policy" "rogue_ap" {
  bucket = aws_s3_bucket.rogue_ap.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAccessPoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::rogue-ap-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:999999999999:accesspoint/rogue-ap"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, restriction allows an unauthorized access point: 1 finding
resource "aws_s3_bucket" "ds_unauth_ap" {
  bucket = "rogue-ap-ds-bucket"
}

data "aws_iam_policy_document" "ds_unauth_ap" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::rogue-ap-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:888888888888:accesspoint/rogue-ds-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_unauth_ap" {
  bucket = aws_s3_bucket.ds_unauth_ap.id
  policy = data.aws_iam_policy_document.ds_unauth_ap.json
}

# Restriction applies to one role only: 1 finding
resource "aws_s3_bucket" "ap_onerole" {
  bucket = "ap-onerole-bucket"
}

resource "aws_s3_bucket_policy" "ap_onerole" {
  bucket = aws_s3_bucket.ap_onerole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-onerole-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Restriction reaches the bucket ARN only, objects stay open: 1 finding
resource "aws_s3_bucket" "ap_bucketarn" {
  bucket = "ap-bucketarn-bucket"
}

resource "aws_s3_bucket_policy" "ap_bucketarn" {
  bucket = aws_s3_bucket.ap_bucketarn.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-bucketarn-bucket",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Restriction narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "ap_extracond" {
  bucket = "ap-extracond-bucket"
}

resource "aws_s3_bucket_policy" "ap_extracond" {
  bucket = aws_s3_bucket.ap_extracond.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-extracond-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}

# Restriction reaches only keys that start with "s", other objects stay open: 1 finding
resource "aws_s3_bucket" "ap_somekeys" {
  bucket = "ap-somekeys-bucket"
}

resource "aws_s3_bucket_policy" "ap_somekeys" {
  bucket = aws_s3_bucket.ap_somekeys.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-somekeys-bucket/s*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# The same narrow pattern after a reference to the bucket: 1 finding
resource "aws_s3_bucket" "ap_refkeys" {
  bucket = "ap-refkeys-bucket"
}

resource "aws_s3_bucket_policy" "ap_refkeys" {
  bucket = aws_s3_bucket.ap_refkeys.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.ap_refkeys.arn}/sample-*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Restriction that exempts objects through NotResource: 1 finding
resource "aws_s3_bucket" "ap_notres" {
  bucket = "ap-notres-bucket"
}

resource "aws_s3_bucket_policy" "ap_notres" {
  bucket = aws_s3_bucket.ap_notres.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "NotResource": "arn:aws:s3:::ap-notres-bucket/public/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Policy from a data source with no restriction, whose name starts with the
# name of one that holds a restriction (apdoc): 1 finding
resource "aws_s3_bucket" "ap_dsname" {
  bucket = "ap-dsname-bucket"
}

data "aws_iam_policy_document" "apdoc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

data "aws_iam_policy_document" "apdoc_open" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ap-dsname-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app"]
    }
  }
}

resource "aws_s3_bucket_policy" "ap_dsname" {
  bucket = aws_s3_bucket.ap_dsname.id
  policy = data.aws_iam_policy_document.apdoc_open.json
}
