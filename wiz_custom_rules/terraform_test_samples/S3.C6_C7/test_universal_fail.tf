# S3.C7 (bucket_secure_transport) - universal - VIOLATING

# Bucket with no bucket policy at all: 2 findings (both protections missing)
resource "aws_s3_bucket" "no_policy" {
  bucket = "no-policy-bucket"
}

# Bucket whose policy has no transport enforcement (allow-only): 2 findings
resource "aws_s3_bucket" "allow_only" {
  bucket = "allow-only-bucket"
}

resource "aws_s3_bucket_policy" "allow_only" {
  bucket = aws_s3_bucket.allow_only.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LogDelivery",
      "Effect": "Allow",
      "Principal": { "Service": "logging.s3.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::allow-only-bucket/*"
    }
  ]
}
POLICY
}

# Bucket denying unencrypted requests but with no TLS-version floor: 1 finding
resource "aws_s3_bucket" "transport_only" {
  bucket = "transport-only-bucket"
}

resource "aws_s3_bucket_policy" "transport_only" {
  bucket = aws_s3_bucket.transport_only.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSSLRequestsOnly",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::transport-only-bucket", "arn:aws:s3:::transport-only-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

# Transport deny covers a single action only: 1 finding
resource "aws_s3_bucket" "narrow_deny" {
  bucket = "narrow-deny-bucket"
}

resource "aws_s3_bucket_policy" "narrow_deny" {
  bucket = aws_s3_bucket.narrow_deny.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NarrowDeny",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": ["arn:aws:s3:::narrow-deny-bucket", "arn:aws:s3:::narrow-deny-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::narrow-deny-bucket", "arn:aws:s3:::narrow-deny-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Transport deny applies to one role only: 1 finding
resource "aws_s3_bucket" "one_role" {
  bucket = "one-role-bucket"
}

resource "aws_s3_bucket_policy" "one_role" {
  bucket = aws_s3_bucket.one_role.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransportForApp",
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::one-role-bucket", "arn:aws:s3:::one-role-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::one-role-bucket", "arn:aws:s3:::one-role-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Denies reach the bucket ARN only, so object requests stay open: 2 findings
resource "aws_s3_bucket" "bucket_level" {
  bucket = "bucket-level-bucket"
}

data "aws_iam_policy_document" "ds_bucketlevel" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.bucket_level.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOldTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.bucket_level.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_level" {
  bucket = aws_s3_bucket.bucket_level.id
  policy = data.aws_iam_policy_document.ds_bucketlevel.json
}

# Transport deny narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "extra_cond" {
  bucket = "extra-cond-bucket"
}

resource "aws_s3_bucket_policy" "extra_cond" {
  bucket = aws_s3_bucket.extra_cond.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransportOneAccount",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::extra-cond-bucket", "arn:aws:s3:::extra-cond-bucket/*"],
      "Condition": {
        "Bool": { "aws:SecureTransport": "false" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::extra-cond-bucket", "arn:aws:s3:::extra-cond-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Denies reference a different bucket: 2 findings
resource "aws_s3_bucket" "foreign_ref" {
  bucket = "foreign-ref-bucket"
}

resource "aws_s3_bucket_policy" "foreign_ref" {
  bucket = aws_s3_bucket.foreign_ref.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.allow_only.arn}", "${aws_s3_bucket.allow_only.arn}/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.allow_only.arn}", "${aws_s3_bucket.allow_only.arn}/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}
