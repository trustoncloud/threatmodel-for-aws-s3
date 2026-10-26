# S3.C156 (bucket_block_unauthorized_service_roles) - allowlist - VIOLATING

# No principal-based block (no policy): 1 finding
resource "aws_s3_bucket" "no_block" {
  bucket = "no-block-bucket"
}

# Block exempts an unauthorized role: 1 finding
resource "aws_s3_bucket" "rogue_role" {
  bucket = "rogue-role-bucket"
}

resource "aws_s3_bucket_policy" "rogue_role" {
  bucket = aws_s3_bucket.rogue_role.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptRole",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::rogue-role-bucket", "arn:aws:s3:::rogue-role-bucket/*"],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::999999999999:role/rogue-role"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, exempts an unauthorized role: 1 finding
resource "aws_s3_bucket" "ds_unauth_role" {
  bucket = "rogue-role-ds-bucket"
}

data "aws_iam_policy_document" "ds_unauth_role" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::rogue-role-ds-bucket", "arn:aws:s3:::rogue-role-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::888888888888:role/rogue-ds-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_unauth_role" {
  bucket = aws_s3_bucket.ds_unauth_role.id
  policy = data.aws_iam_policy_document.ds_unauth_role.json
}

# Block covers a single action only: 1 finding
resource "aws_s3_bucket" "role_deleteonly" {
  bucket = "role-deleteonly-bucket"
}

resource "aws_s3_bucket_policy" "role_deleteonly" {
  bucket = aws_s3_bucket.role_deleteonly.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:DeleteBucket",
      "Resource": ["arn:aws:s3:::role-deleteonly-bucket", "arn:aws:s3:::role-deleteonly-bucket/*"],
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/service-role/authorized-service-role" } }
    }
  ]
}
POLICY
}

# Block reaches the objects only, bucket-level requests stay open: 1 finding
resource "aws_s3_bucket" "role_objonly" {
  bucket = "role-objonly-bucket"
}

resource "aws_s3_bucket_policy" "role_objonly" {
  bucket = aws_s3_bucket.role_objonly.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::role-objonly-bucket/*",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/service-role/authorized-service-role" } }
    }
  ]
}
POLICY
}

# Block narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "role_extracond" {
  bucket = "role-extracond-bucket"
}

resource "aws_s3_bucket_policy" "role_extracond" {
  bucket = aws_s3_bucket.role_extracond.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::role-extracond-bucket", "arn:aws:s3:::role-extracond-bucket/*"],
      "Condition": {
        "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/service-role/authorized-service-role" },
        "StringEquals": { "aws:PrincipalAccount": "999999999999" }
      }
    }
  ]
}
POLICY
}
