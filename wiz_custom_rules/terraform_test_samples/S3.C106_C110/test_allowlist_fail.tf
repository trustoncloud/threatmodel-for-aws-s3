# S3.C110 (access_point_restriction) - allowlist - VIOLATING

# No access point restriction (no policy): 1 finding
resource "aws_s3_bucket" "no_restriction" {
  bucket = "no-restriction-bucket"
}

# Restriction allows an unauthorized access point: 1 finding
resource "aws_s3_bucket" "rogue_ap" {
  bucket = "rogue-ap-bucket"
}

resource "aws_s3_bucket_policy" "rogue_ap" {
  bucket = aws_s3_bucket.rogue_ap.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptAccessPoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::rogue-ap-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:999999999999:accesspoint/rogue-ap"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, restriction allows an unauthorized access point: 1 finding
resource "aws_s3_bucket" "ds_unauth_ap" {
  bucket = "rogue-ap-ds-bucket"
}

data "aws_iam_policy_document" "ds_unauth_ap" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::rogue-ap-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:888888888888:accesspoint/rogue-ds-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_unauth_ap" {
  bucket = aws_s3_bucket.ds_unauth_ap.id
  policy = data.aws_iam_policy_document.ds_unauth_ap.json
}

# Restriction applies to one role only: 1 finding
resource "aws_s3_bucket" "ap_onerole" {
  bucket = "ap-onerole-bucket"
}

resource "aws_s3_bucket_policy" "ap_onerole" {
  bucket = aws_s3_bucket.ap_onerole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-onerole-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Restriction reaches the bucket ARN only, objects stay open: 1 finding
resource "aws_s3_bucket" "ap_bucketarn" {
  bucket = "ap-bucketarn-bucket"
}

resource "aws_s3_bucket_policy" "ap_bucketarn" {
  bucket = aws_s3_bucket.ap_bucketarn.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-bucketarn-bucket",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Restriction narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "ap_extracond" {
  bucket = "ap-extracond-bucket"
}

resource "aws_s3_bucket_policy" "ap_extracond" {
  bucket = aws_s3_bucket.ap_extracond.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-extracond-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}

# Restriction reaches only keys that start with "s", other objects stay open: 1 finding
resource "aws_s3_bucket" "ap_somekeys" {
  bucket = "ap-somekeys-bucket"
}

resource "aws_s3_bucket_policy" "ap_somekeys" {
  bucket = aws_s3_bucket.ap_somekeys.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::ap-somekeys-bucket/s*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# The same narrow pattern after a reference to the bucket: 1 finding
resource "aws_s3_bucket" "ap_refkeys" {
  bucket = "ap-refkeys-bucket"
}

resource "aws_s3_bucket_policy" "ap_refkeys" {
  bucket = aws_s3_bucket.ap_refkeys.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.ap_refkeys.arn}/sample-*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Restriction that exempts objects through NotResource: 1 finding
resource "aws_s3_bucket" "ap_notres" {
  bucket = "ap-notres-bucket"
}

resource "aws_s3_bucket_policy" "ap_notres" {
  bucket = aws_s3_bucket.ap_notres.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "NotResource": "arn:aws:s3:::ap-notres-bucket/public/*",
      "Condition": {
        "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Policy from a data source with no restriction, whose name starts with the
# name of one that holds a restriction (apdoc): 1 finding
resource "aws_s3_bucket" "ap_dsname" {
  bucket = "ap-dsname-bucket"
}

data "aws_iam_policy_document" "apdoc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

data "aws_iam_policy_document" "apdoc_open" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ap-dsname-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app"]
    }
  }
}

resource "aws_s3_bucket_policy" "ap_dsname" {
  bucket = aws_s3_bucket.ap_dsname.id
  policy = data.aws_iam_policy_document.apdoc_open.json
}

# Restriction written with NotAction beside Action, which leaves the named
# actions open: 1 finding
resource "aws_s3_bucket" "ap_notaction" {
  bucket = "ap-notaction-bucket"
}

resource "aws_s3_bucket_policy" "ap_notaction" {
  bucket = aws_s3_bucket.ap_notaction.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "NotAction": "s3:GetObject",
      "Resource": "arn:aws:s3:::ap-notaction-bucket/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" } }
    }
  ]
}
POLICY
}

# Data source restriction with not_actions and not_principals beside the
# covering arguments: 1 finding
resource "aws_s3_bucket" "ap_dsnot" {
  bucket = "ap-dsnot-bucket"
}

data "aws_iam_policy_document" "ap_dsnot" {
  statement {
    effect      = "Deny"
    actions     = ["s3:*"]
    not_actions = ["s3:GetObject"]
    resources   = ["arn:aws:s3:::ap-dsnot-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:role/admin"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "ap_dsnot" {
  bucket = aws_s3_bucket.ap_dsnot.id
  policy = data.aws_iam_policy_document.ap_dsnot.json
}

# The bucket's own policy argument allows an unauthorized access point: 1
# finding
resource "aws_s3_bucket" "inlinerogueap" {
  bucket = "inlinerogueap-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::inlinerogueap-bucket/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:999999999999:accesspoint/rogue-ap" } }
    }
  ]
}
POLICY
}

# The bucket's own policy argument holds a restriction written with
# NotResource beside Resource: 1 finding
resource "aws_s3_bucket" "inlinenotres" {
  bucket = "inlinenotres-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::inlinenotres-bucket/*",
      "NotResource": "arn:aws:s3:::inlinenotres-bucket/public/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" } }
    }
  ]
}
POLICY
}

# Both forms together: the standalone policy holds the authorized restriction,
# the policy argument allows an unauthorized access point: 1 finding
resource "aws_s3_bucket" "apbothforms" {
  bucket = "apbothforms-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::apbothforms-bucket/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap-old" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "apbothforms" {
  bucket = aws_s3_bucket.apbothforms.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::apbothforms-bucket/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" } }
    }
  ]
}
POLICY
}

# Both forms on one bucket, the restriction in the policy argument only (the
# standalone policy holds a transport Deny): only one applies after apply: 1
# finding
resource "aws_s3_bucket" "apsplit" {
  bucket = "apsplit-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::apsplit-bucket/*",
      "Condition": { "StringNotEquals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "apsplit" {
  bucket = aws_s3_bucket.apsplit.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::apsplit-bucket", "arn:aws:s3:::apsplit-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

# Condition operator in lower case: operator names are case sensitive, so
# stringnotequals does not count as StringNotEquals: 1 finding
resource "aws_s3_bucket" "apoplowerjson" {
  bucket = "apoplowerjson-bucket"
}

resource "aws_s3_bucket_policy" "apoplowerjson" {
  bucket = aws_s3_bucket.apoplowerjson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::apoplowerjson-bucket/*",
      "Condition": {
        "stringnotequals": { "s3:DataAccessPointArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap" }
      }
    }
  ]
}
POLICY
}

# Condition operator in lower case in a data source: 1 finding
resource "aws_s3_bucket" "apoplowerhcl" {
  bucket = "apoplowerhcl-bucket"
}

data "aws_iam_policy_document" "ds_apoplowerhcl" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.apoplowerhcl.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "stringnotequals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "apoplowerhcl" {
  bucket = aws_s3_bucket.apoplowerhcl.id
  policy = data.aws_iam_policy_document.ds_apoplowerhcl.json
}

# Data-source policy read through its minified_json attribute allows an
# unauthorized access point: 1 finding
resource "aws_s3_bucket" "apminrogue" {
  bucket = "apminrogue-bucket"
}

data "aws_iam_policy_document" "ds_apminrogue" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.apminrogue.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:999999999999:accesspoint/rogue-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "apminrogue" {
  bucket = aws_s3_bucket.apminrogue.id
  policy = data.aws_iam_policy_document.ds_apminrogue.minified_json
}

# --- Never-created resources and statements the source does not show ---

# A bucket policy that is never created (count = 0) does not protect its bucket,
# even when it holds the required Deny.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "zz-ap-bucket"
}

data "aws_iam_policy_document" "zz_nc_doc" {
  statement {
    sid       = "OnlyAuthorizedAccessPoints"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzncpol" {
  count  = 0
  bucket = aws_s3_bucket.zzncpol.id
  policy = data.aws_iam_policy_document.zz_nc_doc.json
}

# override_policy_documents replaces any written statement with the same
# sid, so a document that sets it cannot prove the Deny.
resource "aws_s3_bucket" "zzoverride" {
  bucket = "zz-ap-bucket"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "OnlyAuthorizedAccessPoints"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "zz_overridden" {
  override_policy_documents = [data.aws_iam_policy_document.zz_override_src.json]

  statement {
    sid       = "OnlyAuthorizedAccessPoints"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzoverride" {
  bucket = aws_s3_bucket.zzoverride.id
  policy = data.aws_iam_policy_document.zz_overridden.json
}

# A dynamic condition block adds conditions the source does not show, which
# can narrow the Deny, so that statement does not count.
resource "aws_s3_bucket" "zzdyncond" {
  bucket = "zz-ap-bucket"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
  statement {
    sid       = "OnlyAuthorizedAccessPoints"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:DataAccessPointArn"
      values   = ["arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap"]
    }

    dynamic "condition" {
      for_each = ["aws:SourceVpce"]
      content {
        test     = "StringEquals"
        variable = condition.value
        values   = ["vpce-0123456789abcdef0"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "zzdyncond" {
  bucket = aws_s3_bucket.zzdyncond.id
  policy = data.aws_iam_policy_document.zz_dyn_cond.json
}
