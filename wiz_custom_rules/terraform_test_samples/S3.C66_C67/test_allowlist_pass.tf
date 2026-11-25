# S3.C67 (bucket_enforce_kms_key) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "kms_enforced" {
  bucket = "kms-enforced-bucket"
}

resource "aws_s3_bucket_policy" "kms_enforced" {
  bucket = aws_s3_bucket.kms_enforced.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthorizedKmsKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::kms-enforced-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy with a reference to the bucket ARN, AWS wildcard principal
resource "aws_s3_bucket" "keyref" {
  bucket = "keyref-bucket"
}

data "aws_iam_policy_document" "ds_keyref" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.keyref.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

resource "aws_s3_bucket_policy" "keyref" {
  bucket = aws_s3_bucket.keyref.id
  policy = data.aws_iam_policy_document.ds_keyref.json
}

# A wildcard reaches a bucket whose name holds dots
resource "aws_s3_bucket" "key_dotted" {
  bucket = "logs.example.com"
}

resource "aws_s3_bucket_policy" "key_dotted" {
  bucket = aws_s3_bucket.key_dotted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

# Deny set in the policy argument of the bucket, action written in lower case
resource "aws_s3_bucket" "inline_key" {
  bucket = "inline-key-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:putobject",
      "Resource": "arn:aws:s3:::inline-key-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

# Policy argument of the bucket built by a data source, action in mixed case
resource "aws_s3_bucket" "inline_key_ds" {
  bucket = "inline-key-ds-bucket"
  policy = data.aws_iam_policy_document.inline_key_ds.json
}

data "aws_iam_policy_document" "inline_key_ds" {
  statement {
    effect    = "Deny"
    actions   = ["S3:PutObject"]
    resources = ["arn:aws:s3:::inline-key-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

# Both forms: only one applies after apply, so each holds the full Deny; the
# policy argument also holds another statement
resource "aws_s3_bucket" "both_key" {
  bucket = "both-key-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/reader" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::both-key-bucket/*"
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::both-key-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_key" {
  bucket = aws_s3_bucket.both_key.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "S3:*",
      "Resource": "arn:aws:s3:::both-key-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

# Action pattern that covers PutObject, IfExists operator
resource "aws_s3_bucket" "wildput" {
  bucket = "wildput-bucket"
}

resource "aws_s3_bucket_policy" "wildput" {
  bucket = aws_s3_bucket.wildput.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:Put*",
      "Resource": "arn:aws:s3:::wildput-bucket/*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

# Action pattern with "?" in a data source; condition key names are not case
# sensitive
resource "aws_s3_bucket" "qmarkput" {
  bucket = "qmarkput-bucket"
}

data "aws_iam_policy_document" "ds_qmarkput" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObj?ct"]
    resources = ["${aws_s3_bucket.qmarkput.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "S3:X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

resource "aws_s3_bucket_policy" "qmarkput" {
  bucket = aws_s3_bucket.qmarkput.id
  policy = data.aws_iam_policy_document.ds_qmarkput.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket that is never created (count = 0, or for_each over an empty
# collection) is not judged, even with no bucket policy.
resource "aws_s3_bucket" "zzncsubj" {
  count  = 0
  bucket = "zz-kms-bucket"
}

resource "aws_s3_bucket" "zzfesubj" {
  for_each = toset([])
  bucket = "zz-kms-bucket"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "zz-kms-bucket"
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
    sid       = "RequireAuthorizedKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}
