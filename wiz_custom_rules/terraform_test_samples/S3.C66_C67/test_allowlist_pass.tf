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
