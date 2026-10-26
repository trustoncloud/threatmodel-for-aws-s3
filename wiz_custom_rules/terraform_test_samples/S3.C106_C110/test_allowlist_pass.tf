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
