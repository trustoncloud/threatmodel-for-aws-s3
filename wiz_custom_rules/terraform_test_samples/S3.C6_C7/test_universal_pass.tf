# S3.C7 (bucket_secure_transport) - universal - COMPLIANT (0 findings)
# Each bucket policy carries BOTH required Deny statements: unencrypted
# requests (aws:SecureTransport false) and TLS versions below 1.2.

resource "aws_s3_bucket" "heredoc_secure" {
  bucket = "heredoc-secure-bucket"
}

resource "aws_s3_bucket_policy" "heredoc_secure" {
  bucket = aws_s3_bucket.heredoc_secure.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::heredoc-secure-bucket", "arn:aws:s3:::heredoc-secure-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::heredoc-secure-bucket", "arn:aws:s3:::heredoc-secure-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Same two protections expressed through a policy document data source
resource "aws_s3_bucket" "datasource_secure" {
  bucket = "datasource-secure-bucket"
}

data "aws_iam_policy_document" "secure_transport" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::datasource-secure-bucket", "arn:aws:s3:::datasource-secure-bucket/*"]
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
    resources = ["arn:aws:s3:::datasource-secure-bucket", "arn:aws:s3:::datasource-secure-bucket/*"]
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

resource "aws_s3_bucket_policy" "datasource_secure" {
  bucket = aws_s3_bucket.datasource_secure.id
  policy = data.aws_iam_policy_document.secure_transport.json
}

# Resources given as references to the bucket ARN, AWS wildcard principal
resource "aws_s3_bucket" "arnref_doc" {
  bucket = "arnref-doc-bucket"
}

resource "aws_s3_bucket_policy" "arnref_doc" {
  bucket = aws_s3_bucket.arnref_doc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": { "AWS": "*" },
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.arnref_doc.arn}", "${aws_s3_bucket.arnref_doc.arn}/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": { "AWS": "*" },
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.arnref_doc.arn}", "${aws_s3_bucket.arnref_doc.arn}/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Data source with references, the TLS floor split into bucket and object statements
resource "aws_s3_bucket" "arnref_ds" {
  bucket = "arnref-ds-bucket"
}

data "aws_iam_policy_document" "ds_arnref" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.arnref_ds.arn, "${aws_s3_bucket.arnref_ds.arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOldTlsBucket"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.arnref_ds.arn]
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

  statement {
    sid       = "DenyOldTlsObjects"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.arnref_ds.arn}/*"]
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

resource "aws_s3_bucket_policy" "arnref_ds" {
  bucket = aws_s3_bucket.arnref_ds.id
  policy = data.aws_iam_policy_document.ds_arnref.json
}
