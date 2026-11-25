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

# A wildcard reaches a bucket whose name holds dots
resource "aws_s3_bucket" "dotted" {
  bucket = "logs.example.com"
}

resource "aws_s3_bucket_policy" "dotted" {
  bucket = aws_s3_bucket.dotted.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::logs.example.com", "arn:aws:s3:::logs.example.com/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# The bucket's own policy argument holds both Denies, each exempting AWS
# service principals with aws:PrincipalIsAWSService false under BoolIfExists
# (anonymous requests omit the key and stay denied), the TLS Deny in its
# IfExists spelling
resource "aws_s3_bucket" "inline_policy" {
  bucket = "inline-policy-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::inline-policy-bucket", "arn:aws:s3:::inline-policy-bucket/*"],
      "Condition": { "BoolIfExists": { "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::inline-policy-bucket", "arn:aws:s3:::inline-policy-bucket/*"],
      "Condition": {
        "NumericLessThanIfExists": { "s3:TlsVersion": "1.2" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
POLICY
}

# The bucket's own policy argument and an aws_s3_bucket_policy each hold both
# Denies, so whichever applies last, the bucket keeps them
resource "aws_s3_bucket" "both_forms" {
  bucket = "both-forms-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::both-forms-bucket", "arn:aws:s3:::both-forms-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::both-forms-bucket", "arn:aws:s3:::both-forms-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_forms" {
  bucket = aws_s3_bucket.both_forms.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::both-forms-bucket", "arn:aws:s3:::both-forms-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::both-forms-bucket", "arn:aws:s3:::both-forms-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
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
  bucket = "zz-transport-bucket"
}

resource "aws_s3_bucket" "zzfesubj" {
  for_each = toset([])
  bucket = "zz-transport-bucket"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "zz-transport-bucket"
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
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

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
    resources = ["*"]

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

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}

# Action names are not case sensitive in IAM, so "S3:*" covers every S3
# action.
resource "aws_s3_bucket" "zzactcase" {
  bucket = "zz-transport-bucket"
}

resource "aws_s3_bucket_policy" "zzactcase" {
  bucket = aws_s3_bucket.zzactcase.id
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "S3:*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}, {"Effect": "Deny", "Principal": "*", "Action": ["S3:*"], "Resource": "*", "Condition": {"NumericLessThan": {"s3:TlsVersion": "1.2"}}}]}
POLICY
}
