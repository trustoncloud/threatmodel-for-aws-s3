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
          "aws:PrincipalArn": "arn:aws:iam::123456789012:role/service-role/authorized-service-role"
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
      values   = ["arn:aws:iam::123456789012:role/service-role/authorized-service-role"]
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
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/service-role/authorized-service-role" } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.rolesplit.arn}/*",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/service-role/authorized-service-role" } }
    }
  ]
}
POLICY
}
