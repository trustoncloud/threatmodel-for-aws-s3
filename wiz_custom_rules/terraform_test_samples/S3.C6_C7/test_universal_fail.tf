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

# Object pattern leaves keys out (literal ARN): 2 findings
resource "aws_s3_bucket" "narrow_objects" {
  bucket = "narrow-objects-bucket"
}

resource "aws_s3_bucket_policy" "narrow_objects" {
  bucket = aws_s3_bucket.narrow_objects.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::narrow-objects-bucket", "arn:aws:s3:::narrow-objects-bucket/s*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::narrow-objects-bucket", "arn:aws:s3:::narrow-objects-bucket/sample-object"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Object pattern leaves keys out (reference to the bucket ARN): 2 findings
resource "aws_s3_bucket" "narrow_ref" {
  bucket = "narrow-ref-bucket"
}

resource "aws_s3_bucket_policy" "narrow_ref" {
  bucket = aws_s3_bucket.narrow_ref.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.narrow_ref.arn}", "${aws_s3_bucket.narrow_ref.arn}/s*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.narrow_ref.arn}", "${aws_s3_bucket.narrow_ref.arn}/logs/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Transport deny written with NotResource is never counted: 1 finding
resource "aws_s3_bucket" "not_resource" {
  bucket = "not-resource-bucket"
}

data "aws_iam_policy_document" "ds_notresource" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_resources = ["arn:aws:s3:::not-resource-bucket/public/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyOldTls"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [aws_s3_bucket.not_resource.arn, "${aws_s3_bucket.not_resource.arn}/*"]

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "not_resource" {
  bucket = aws_s3_bucket.not_resource.id
  policy = data.aws_iam_policy_document.ds_notresource.json
}

# Bucket whose policy names the data source "guard_extra", which allows only.
# The compliant data source "guard" shares the start of that name and belongs
# to no policy here: 2 findings
resource "aws_s3_bucket" "ds_prefix" {
  bucket = "ds-prefix-bucket"
}

data "aws_iam_policy_document" "guard_extra" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.ds_prefix.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/reader"]
    }
  }
}

data "aws_iam_policy_document" "guard" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*"]

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
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*"]

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

resource "aws_s3_bucket_policy" "ds_prefix" {
  bucket = aws_s3_bucket.ds_prefix.id
  policy = data.aws_iam_policy_document.guard_extra.json
}
