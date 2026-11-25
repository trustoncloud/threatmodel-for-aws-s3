# S3.C151 (bucket_policy_principal_check) - allowlist - VIOLATING

# Grants access to an unauthorized principal: 1 finding
resource "aws_s3_bucket" "rogue_principal" {
  bucket = "rogue-principal-bucket"
}

resource "aws_s3_bucket_policy" "rogue_principal" {
  bucket = aws_s3_bucket.rogue_principal.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRogue",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::999999999999:role/rogue-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-principal-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy with an omitted effect (defaults to Allow) granting an
# unauthorized principal: 1 finding
resource "aws_s3_bucket" "rogue_ds" {
  bucket = "rogue-ds-bucket"
}

data "aws_iam_policy_document" "rogue_ds" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::rogue-ds-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::999999999999:role/rogue-ds-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "rogue_ds" {
  bucket = aws_s3_bucket.rogue_ds.id
  policy = data.aws_iam_policy_document.rogue_ds.json
}

# Data-source Allow to every principal (type "*"), effect left out: 1 finding
resource "aws_s3_bucket" "public_ds" {
  bucket = "public-ds-bucket"
}

data "aws_iam_policy_document" "public_ds" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::public-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "public_ds" {
  bucket = aws_s3_bucket.public_ds.id
  policy = data.aws_iam_policy_document.public_ds.json
}

# The bucket's own policy argument grants an unauthorized principal: 1 finding
resource "aws_s3_bucket" "inlinerogue" {
  bucket = "inlinerogue-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::999999999999:role/inline-rogue-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::inlinerogue-bucket/*"
    }
  ]
}
POLICY
}

# The policy argument names a data source granting every principal: 1 finding
resource "aws_s3_bucket" "inlinedspublic" {
  bucket = "inlinedspublic-bucket"
  policy = data.aws_iam_policy_document.inlinedspublic.json
}

data "aws_iam_policy_document" "inlinedspublic" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::inlinedspublic-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Both forms together: the standalone policy grants only authorized
# principals, the policy argument an unauthorized one: 1 finding
resource "aws_s3_bucket" "twoforms" {
  bucket = "twoforms-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/authorized-role-old" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::twoforms-bucket/*"
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "twoforms" {
  bucket = aws_s3_bucket.twoforms.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/authorized-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::twoforms-bucket/*"
    }
  ]
}
POLICY
}

# Allow to a canonical user while none is authorized: 1 finding
resource "aws_s3_bucket" "canonicaljson" {
  bucket = "canonicaljson-bucket"
}

resource "aws_s3_bucket_policy" "canonicaljson" {
  bucket = aws_s3_bucket.canonicaljson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/authorized-role",
        "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::canonicaljson-bucket/*"
    }
  ]
}
POLICY
}

# Data source granting a canonical user, effect left out: 1 finding
resource "aws_s3_bucket" "canonicalds" {
  bucket = "canonicalds-bucket"
}

data "aws_iam_policy_document" "canonicalds" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::canonicalds-bucket/*"]

    principals {
      type        = "CanonicalUser"
      identifiers = ["79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"]
    }
  }
}

resource "aws_s3_bucket_policy" "canonicalds" {
  bucket = aws_s3_bucket.canonicalds.id
  policy = data.aws_iam_policy_document.canonicalds.json
}

# Allow written with NotPrincipal grants every principal except those it lists,
# even when it lists only authorized principals: 1 finding
resource "aws_s3_bucket" "npjson" {
  bucket = "npjson-bucket"
}

resource "aws_s3_bucket_policy" "npjson" {
  bucket = aws_s3_bucket.npjson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "NotPrincipal": { "AWS": "arn:aws:iam::123456789012:role/authorized-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::npjson-bucket/*"
    }
  ]
}
POLICY
}

# The bucket's own policy argument holds an Allow written with NotPrincipal:
# 1 finding
resource "aws_s3_bucket" "npinline" {
  bucket = "npinline-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "NotPrincipal": { "AWS": "arn:aws:iam::999999999999:role/excluded-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::npinline-bucket/*"
    }
  ]
}
POLICY
}

# Data-source statement with not_principals and the effect left out (defaults
# to Allow), beside an Allow for an authorized principal: 1 finding
resource "aws_s3_bucket" "ds_npblock" {
  bucket = "ds-npblock-bucket"
}

data "aws_iam_policy_document" "ds_npblock" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-npblock-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }

  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-npblock-bucket/*"]

    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/authorized-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_npblock" {
  bucket = aws_s3_bucket.ds_npblock.id
  policy = data.aws_iam_policy_document.ds_npblock.json
}

# The policy argument names a data source whose Allow uses not_principals:
# 1 finding
resource "aws_s3_bucket" "ds_npbucketarg" {
  bucket = "ds-npbucketarg-bucket"
  policy = data.aws_iam_policy_document.ds_npbucketarg.json
}

data "aws_iam_policy_document" "ds_npbucketarg" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-npbucketarg-bucket/*"]

    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::999999999999:root"]
    }
  }
}

# --- Never-created resources and statements the source does not show ---

# A count other than 0 creates the bucket, so it is judged.
resource "aws_s3_bucket" "zzcounted" {
  count  = 1
  bucket = "zz-principal-bucket"
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:GetObject", "Resource": "*"}]}
POLICY
}

# A dynamic statement block generates statements the source does not show,
# which may grant more than the written statements.
resource "aws_s3_bucket" "zzdynadd" {
  bucket = "zz-principal-bucket"
}

data "aws_iam_policy_document" "zz_dyn_added" {
  statement {
    sid       = "AuthorizedRole"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/authorized-role"]
    }
  }

  dynamic "statement" {
    for_each = ["s3:GetObject"]
    content {
      effect    = "Allow"
      actions   = [statement.value]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = ["arn:aws:iam::999999999999:root"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "zzdynadd" {
  bucket = aws_s3_bucket.zzdynadd.id
  policy = data.aws_iam_policy_document.zz_dyn_added.json
}

# source_policy_documents adds statements the document does not write out.
resource "aws_s3_bucket" "zzsrcadd" {
  bucket = "zz-principal-bucket"
}

data "aws_iam_policy_document" "zz_src_extra" {
  statement {
    sid       = "ReadObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::999999999999:root"]
    }
  }
}

data "aws_iam_policy_document" "zz_src_added" {
  source_policy_documents = [data.aws_iam_policy_document.zz_src_extra.json]

  statement {
    sid       = "AuthorizedRole"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/authorized-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}

# A dynamic principals block generates principals the source does not show.
resource "aws_s3_bucket" "zzdynprinc" {
  bucket = "zz-principal-bucket"
}

data "aws_iam_policy_document" "zz_dyn_principals" {
  statement {
    sid       = "AuthorizedRole"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/authorized-role"]
    }
  }

  statement {
    sid       = "GeneratedPrincipals"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    dynamic "principals" {
      for_each = ["AWS"]
      content {
        type        = principals.value
        identifiers = ["arn:aws:iam::999999999999:root"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "zzdynprinc" {
  bucket = aws_s3_bucket.zzdynprinc.id
  policy = data.aws_iam_policy_document.zz_dyn_principals.json
}
