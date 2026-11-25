# S3.C156 (bucket_block_unauthorized_service_roles) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "role_restricted" {
  bucket = "role-restricted-bucket"
}

resource "aws_s3_bucket_policy" "role_restricted" {
  bucket = aws_s3_bucket.role_restricted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAuthorizedRole",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::role-restricted-bucket",
        "arn:aws:s3:::role-restricted-bucket/*"
      ],
      "Condition": {
        "ArnNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, exempts only the authorized role: no finding
resource "aws_s3_bucket" "role_ds" {
  bucket = "role-ds-bucket"
}

data "aws_iam_policy_document" "role_ds" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::role-ds-bucket", "arn:aws:s3:::role-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"]
    }
  }
}

resource "aws_s3_bucket_policy" "role_ds" {
  bucket = aws_s3_bucket.role_ds.id
  policy = data.aws_iam_policy_document.role_ds.json
}

# Bucket and objects split across two statements, ArnNotEquals operator
resource "aws_s3_bucket" "rolesplit" {
  bucket = "rolesplit-bucket"
}

resource "aws_s3_bucket_policy" "rolesplit" {
  bucket = aws_s3_bucket.rolesplit.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.rolesplit.arn}",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.rolesplit.arn}/*",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
    }
  ]
}
POLICY
}

# A wildcard reaches a bucket whose name holds dots
resource "aws_s3_bucket" "role_dotted" {
  bucket = "logs.example.com"
}

resource "aws_s3_bucket_policy" "role_dotted" {
  bucket = aws_s3_bucket.role_dotted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
    }
  ]
}
POLICY
}

# Only the bucket's own policy argument holds the Deny: every service-linked
# role is blocked except the authorized Macie role
resource "aws_s3_bucket" "inlinejson" {
  bucket = "inlinejson-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyServiceLinkedRoles",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::inlinejson-bucket", "arn:aws:s3:::inlinejson-bucket/*"],
      "Condition": {
        "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" },
        "StringNotLike": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" }
      }
    }
  ]
}
POLICY
}

# The policy argument names a data source; StringLike on the AWSServiceRoleFor
# name pattern
resource "aws_s3_bucket" "inlinedsref" {
  bucket = "inlinedsref-bucket"
  policy = data.aws_iam_policy_document.inlinedsref.json
}

data "aws_iam_policy_document" "inlinedsref" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::inlinedsref-bucket", "arn:aws:s3:::inlinedsref-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:*/AWSServiceRoleFor*"]
    }
  }
}

# Standalone policy, a partition wildcard in the pattern
resource "aws_s3_bucket" "anypartition" {
  bucket = "anypartition-bucket"
}

resource "aws_s3_bucket_policy" "anypartition" {
  bucket = aws_s3_bucket.anypartition.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "*" },
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.anypartition.arn}", "${aws_s3_bucket.anypartition.arn}/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:*:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# Both forms on one bucket: only one applies after apply, so each holds the
# full Deny
resource "aws_s3_bucket" "bothfull" {
  bucket = "bothfull-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::bothfull-bucket", "arn:aws:s3:::bothfull-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "bothfull" {
  bucket = aws_s3_bucket.bothfull.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.bothfull.arn}", "${aws_s3_bucket.bothfull.arn}/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# Every IAM ARN in any partition, with ArnLike: no finding
resource "aws_s3_bucket" "everyiam" {
  bucket = "everyiam-bucket"
}

resource "aws_s3_bucket_policy" "everyiam" {
  bucket = aws_s3_bucket.everyiam.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::everyiam-bucket", "arn:aws:s3:::everyiam-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:*:iam::*:*" } }
    }
  ]
}
POLICY
}

# StringLike "*" reaches every principal: no finding
resource "aws_s3_bucket" "starlike" {
  bucket = "starlike-bucket"
}

resource "aws_s3_bucket_policy" "starlike" {
  bucket = aws_s3_bucket.starlike.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::starlike-bucket", "arn:aws:s3:::starlike-bucket/*"],
      "Condition": { "StringLike": { "aws:PrincipalArn": "*" } }
    }
  ]
}
POLICY
}

# An account of twelve "?" matches every account ID: no finding
resource "aws_s3_bucket" "acctqmark" {
  bucket = "acctqmark-bucket"
}

resource "aws_s3_bucket_policy" "acctqmark" {
  bucket = aws_s3_bucket.acctqmark.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::acctqmark-bucket", "arn:aws:s3:::acctqmark-bucket/*"],
      "Condition": { "StringLike": { "aws:PrincipalArn": "arn:aws:iam::????????????:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# An account of "?*" matches every account ID: no finding
resource "aws_s3_bucket" "acctqstar" {
  bucket = "acctqstar-bucket"
}

resource "aws_s3_bucket_policy" "acctqstar" {
  bucket = aws_s3_bucket.acctqstar.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::acctqstar-bucket", "arn:aws:s3:::acctqstar-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::?*:role/aws-service-role/*" } }
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
  bucket = "zz-slr-bucket"
}

resource "aws_s3_bucket" "zzfesubj" {
  for_each = toset([])
  bucket = "zz-slr-bucket"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "zz-slr-bucket"
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
    sid       = "DenyServiceLinkedRoles"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/aws-service-role/*"]
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
  bucket = "zz-slr-bucket"
}

resource "aws_s3_bucket_policy" "zzactcase" {
  bucket = aws_s3_bucket.zzactcase.id
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "S3:*", "Resource": "*", "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"}}}]}
POLICY
}
