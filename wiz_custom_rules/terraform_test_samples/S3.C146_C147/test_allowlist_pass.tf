# S3.C147 (bucket_enforce_ssec) - allowlist - COMPLIANT (0 findings)

# Required bucket enforcing SSE-C on PutObject
resource "aws_s3_bucket" "ssec_required" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssec_required" {
  bucket = aws_s3_bucket.ssec_required.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyMissingSsecHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Ordinary bucket: out of scope for this control
resource "aws_s3_bucket" "ordinary" {
  bucket = "ordinary-bucket"
}

# Path entry mixed-bucket/secure/ enforced on that path, via a reference
resource "aws_s3_bucket" "mixedpass" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixedpass" {
  bucket = aws_s3_bucket.mixedpass.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.mixedpass.arn}/secure/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/ enforced by a pattern that ends at the path name
resource "aws_s3_bucket" "mixedwide" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixedwide" {
  bucket = aws_s3_bucket.mixedwide.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/secure*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Required bucket: an object key is never empty, so "/?*" after the bucket reaches every object
resource "aws_s3_bucket" "ssec_nonempty" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssec_nonempty" {
  bucket = aws_s3_bucket.ssec_nonempty.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.ssec_nonempty.arn}/?*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Required bucket enforcing SSE-C in the policy argument of the bucket, action
# written in lower case
resource "aws_s3_bucket" "inline_ssec" {
  bucket = "ssec-required-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:putobject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption-customer-algorithm": "AES256" }
      }
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/ enforced in the policy argument of the bucket
# built by a data source, action in mixed case
resource "aws_s3_bucket" "inline_mixed_ds" {
  bucket = "mixed-bucket"
  policy = data.aws_iam_policy_document.inline_mixed_ds.json
}

data "aws_iam_policy_document" "inline_mixed_ds" {
  statement {
    effect    = "Deny"
    actions   = ["S3:PutObject"]
    resources = ["arn:aws:s3:::mixed-bucket/secure/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["true"]
    }
  }
}

# Both forms: only one applies after apply, so each holds the full Deny; the
# policy argument also holds another statement
resource "aws_s3_bucket" "both_ssec" {
  bucket = "ssec-required-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/reader" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*"
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption-customer-algorithm": "AES256" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_ssec" {
  bucket = aws_s3_bucket.both_ssec.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "S3:*",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Required bucket: action pattern that covers PutObject
resource "aws_s3_bucket" "ssecwildput" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecwildput" {
  bucket = aws_s3_bucket.ssecwildput.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:Put*",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Required bucket: action pattern with "?" in a data source; condition key
# names are not case sensitive
resource "aws_s3_bucket" "ssecqmarkput" {
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "ds_ssecqmarkput" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObj?ct"]
    resources = ["${aws_s3_bucket.ssecqmarkput.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "S3:X-Amz-Server-Side-Encryption-Customer-Algorithm"
      values   = ["AES256"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssecqmarkput" {
  bucket = aws_s3_bucket.ssecqmarkput.id
  policy = data.aws_iam_policy_document.ds_ssecqmarkput.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket that is never created (count = 0, or for_each over an empty
# collection) is not judged, even with no bucket policy.
resource "aws_s3_bucket" "zzncsubj" {
  count  = 0
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket" "zzfesubj" {
  for_each = toset([])
  bucket = "ssec-required-bucket"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "ssec-required-bucket"
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
    sid       = "RequireSsec"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["AES256"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}
