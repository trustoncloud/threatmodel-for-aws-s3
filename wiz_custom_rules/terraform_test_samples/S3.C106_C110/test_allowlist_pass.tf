# S3.C110 (access_point_restriction) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "ap_restricted" {
  bucket = "ap-restricted-bucket"
}

resource "aws_s3_bucket_policy" "ap_restricted" {
  bucket = aws_s3_bucket.ap_restricted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAuthorizedAccessPoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::ap-restricted-bucket",
        "arn:aws:s3:::ap-restricted-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, authorized access point: no finding
resource "aws_s3_bucket" "ap_ds" {
  bucket = "ap-ds-bucket"
}

data "aws_iam_policy_document" "ap_ds" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::ap-ds-bucket/*"]

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

resource "aws_s3_bucket_policy" "ap_ds" {
  bucket = aws_s3_bucket.ap_ds.id
  policy = data.aws_iam_policy_document.ap_ds.json
}

# Deny on the objects only, given as a reference: bucket settings stay reachable
resource "aws_s3_bucket" "apobj" {
  bucket = "apobj-bucket"
}

resource "aws_s3_bucket_policy" "apobj" {
  bucket = aws_s3_bucket.apobj.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.apobj.arn}/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# A bucket name with dots, reached by a wildcard that covers every bucket
resource "aws_s3_bucket" "ap_dotted" {
  bucket = "ap.dotted.example.com"
}

resource "aws_s3_bucket_policy" "ap_dotted" {
  bucket = aws_s3_bucket.ap_dotted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# A pattern that starts at the bucket name still reaches every object
resource "aws_s3_bucket" "ap_wide" {
  bucket = "ap-wide-bucket"
}

resource "aws_s3_bucket_policy" "ap_wide" {
  bucket = aws_s3_bucket.ap_wide.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-wide-bucket*",
      "Condition": {
        "StringNotEqualsIfExists": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# An object key is never empty, so "/?*" after the bucket reaches every object
resource "aws_s3_bucket" "ap_nonempty" {
  bucket = "ap-nonempty-bucket"
}

resource "aws_s3_bucket_policy" "ap_nonempty" {
  bucket = aws_s3_bucket.ap_nonempty.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.ap_nonempty.arn}/?*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket" "aplit_nonempty" {
  bucket = "ap-nonempty-literal"
}

resource "aws_s3_bucket_policy" "aplit_nonempty" {
  bucket = aws_s3_bucket.aplit_nonempty.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-nonempty-literal/?*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Only the bucket's own policy argument holds the restriction: no finding
resource "aws_s3_bucket" "inlineap" {
  bucket = "inlineap-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAuthorizedAccessPoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::inlineap-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"
        }
      }
    }
  ]
}
POLICY
}

# The policy argument names a data source that holds the restriction: no
# finding
resource "aws_s3_bucket" "inlineapds" {
  bucket = "inlineapds-bucket"
  policy = data.aws_iam_policy_document.inlineapds.json
}

data "aws_iam_policy_document" "inlineapds" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::inlineapds-bucket/*"]

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

# Both forms on one bucket: only one applies after apply, so each holds the
# full restriction: no finding
resource "aws_s3_bucket" "apboth" {
  bucket = "apboth-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::apboth-bucket/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "apboth" {
  bucket = aws_s3_bucket.apboth.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.apboth.arn}/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" } }
    }
  ]
}
POLICY
}

# Data-source policy read through its minified_json attribute: no finding
resource "aws_s3_bucket" "apminjson" {
  bucket = "apminjson-bucket"
}

data "aws_iam_policy_document" "ds_apminjson" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.apminjson.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "apminjson" {
  bucket = aws_s3_bucket.apminjson.id
  policy = data.aws_iam_policy_document.ds_apminjson.minified_json
}

# --- Never-created resources and statements the source does not show ---

# A bucket that is never created (count = 0, or for_each over an empty
# collection) is not judged, even with no bucket policy.
resource "aws_s3_bucket" "zzncsubj" {
  count  = 0
  bucket = "zz-ap-bucket"
}

resource "aws_s3_bucket" "zzfesubj" {
  for_each = toset([])
  bucket = "zz-ap-bucket"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "zz-ap-bucket"
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
    sid       = "OnlyAuthorizedAccessPoints"
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

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}

# Action names are not case sensitive in IAM, so "S3:*" covers every S3
# action.
resource "aws_s3_bucket" "zzactcase" {
  bucket = "zz-ap-bucket"
}

resource "aws_s3_bucket_policy" "zzactcase" {
  bucket = aws_s3_bucket.zzactcase.id
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "S3:*", "Resource": "*", "Condition": {"StringNotEquals": {"s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"}}}]}
POLICY
}
