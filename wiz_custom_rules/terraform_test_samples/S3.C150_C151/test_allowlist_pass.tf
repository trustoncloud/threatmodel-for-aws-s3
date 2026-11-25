# S3.C151 (bucket_policy_principal_check) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "principal_ok" {
  bucket = "principal-ok-bucket"
}

resource "aws_s3_bucket_policy" "principal_ok" {
  bucket = aws_s3_bucket.principal_ok.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAuthorizedPrincipals",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::123456789012:role/authorized-role",
          "arn:aws:iam::123456789012:root"
        ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::principal-ok-bucket/*"
    }
  ]
}
POLICY
}

# Only the bucket's own policy argument grants access, to authorized
# principals
resource "aws_s3_bucket" "inlineok" {
  bucket = "inlineok-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAuthorizedRole",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/authorized-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::inlineok-bucket/*"
    }
  ]
}
POLICY
}

# The policy argument names a data source that grants an authorized principal
resource "aws_s3_bucket" "inlinedsok" {
  bucket = "inlinedsok-bucket"
  policy = data.aws_iam_policy_document.inlinedsok.json
}

data "aws_iam_policy_document" "inlinedsok" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::inlinedsok-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }
}

# A Deny naming a canonical user grants nothing
resource "aws_s3_bucket" "canonicaldeny" {
  bucket = "canonicaldeny-bucket"
}

resource "aws_s3_bucket_policy" "canonicaldeny" {
  bucket = aws_s3_bucket.canonicaldeny.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be" },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::canonicaldeny-bucket/*"
    }
  ]
}
POLICY
}

# A Deny written with NotPrincipal grants nothing; the Allow names an
# authorized principal
resource "aws_s3_bucket" "npdeny" {
  bucket = "npdeny-bucket"
}

resource "aws_s3_bucket_policy" "npdeny" {
  bucket = aws_s3_bucket.npdeny.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAuthorizedRole",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/authorized-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::npdeny-bucket/*"
    },
    {
      "Sid": "DenyOthers",
      "Effect": "Deny",
      "NotPrincipal": { "AWS": "arn:aws:iam::123456789012:role/authorized-role" },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::npdeny-bucket/*"
    }
  ]
}
POLICY
}

# Data-source form of the same pattern: a Deny with not_principals beside an
# Allow for an authorized principal
resource "aws_s3_bucket" "ds_npexcept" {
  bucket = "ds-npexcept-bucket"
}

data "aws_iam_policy_document" "ds_npexcept" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-npexcept-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/authorized-role"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::ds-npexcept-bucket/*"]

    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/authorized-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_npexcept" {
  bucket = aws_s3_bucket.ds_npexcept.id
  policy = data.aws_iam_policy_document.ds_npexcept.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket that is never created is not judged, whatever its policy grants.
resource "aws_s3_bucket" "zzncsubj" {
  count  = 0
  bucket = "zz-principal-bucket"
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:GetObject", "Resource": "*"}]}
POLICY
}

# A bucket policy that is never created grants nothing.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "zz-principal-bucket"
}

resource "aws_s3_bucket_policy" "zzncpol" {
  count  = 0
  bucket = aws_s3_bucket.zzncpol.id
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:GetObject", "Resource": "*"}]}
POLICY
}
