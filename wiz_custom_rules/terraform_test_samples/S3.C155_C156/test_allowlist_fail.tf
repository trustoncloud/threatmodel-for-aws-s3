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
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
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
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
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
        "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" },
        "StringEquals": { "aws:PrincipalAccount": "999999999999" }
      }
    }
  ]
}
POLICY
}

# Object pattern leaves keys out (literal ARN): 1 finding
resource "aws_s3_bucket" "role_narrow" {
  bucket = "role-narrow-bucket"
}

resource "aws_s3_bucket_policy" "role_narrow" {
  bucket = aws_s3_bucket.role_narrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::role-narrow-bucket", "arn:aws:s3:::role-narrow-bucket/s*"],
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
    }
  ]
}
POLICY
}

# One object named in place of every object (reference to the bucket ARN): 1 finding
resource "aws_s3_bucket" "role_oneobject" {
  bucket = "role-oneobject-bucket"
}

resource "aws_s3_bucket_policy" "role_oneobject" {
  bucket = aws_s3_bucket.role_oneobject.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.role_oneobject.arn}", "${aws_s3_bucket.role_oneobject.arn}/sample-object"],
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" } }
    }
  ]
}
POLICY
}

# Deny written with NotResource is never counted: 1 finding
resource "aws_s3_bucket" "role_notresource" {
  bucket = "role-notresource-bucket"
}

data "aws_iam_policy_document" "role_notresource" {
  statement {
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_resources = ["arn:aws:s3:::role-notresource-bucket/public/*"]

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"]
    }
  }
}

resource "aws_s3_bucket_policy" "role_notresource" {
  bucket = aws_s3_bucket.role_notresource.id
  policy = data.aws_iam_policy_document.role_notresource.json
}

# The bucket's own policy argument blocks one service only: 1 finding
resource "aws_s3_bucket" "inlineonesvc" {
  bucket = "inlineonesvc-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::inlineonesvc-bucket", "arn:aws:s3:::inlineonesvc-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/support.amazonaws.com/*" } }
    }
  ]
}
POLICY
}

# The bucket's own policy argument exempts an unauthorized service-linked
# role: 1 finding
resource "aws_s3_bucket" "inlineexempt" {
  bucket = "inlineexempt-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::inlineexempt-bucket", "arn:aws:s3:::inlineexempt-bucket/*"],
      "Condition": {
        "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" },
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/support.amazonaws.com/*" }
      }
    }
  ]
}
POLICY
}

# Pattern for one account only: 1 finding
resource "aws_s3_bucket" "oneacct" {
  bucket = "oneacct-bucket"
}

resource "aws_s3_bucket_policy" "oneacct" {
  bucket = aws_s3_bucket.oneacct.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::oneacct-bucket", "arn:aws:s3:::oneacct-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# Pattern on the customer service-role path, which holds no service-linked
# role: 1 finding
resource "aws_s3_bucket" "custpath" {
  bucket = "custpath-bucket"
}

resource "aws_s3_bucket_policy" "custpath" {
  bucket = aws_s3_bucket.custpath.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::custpath-bucket", "arn:aws:s3:::custpath-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/service-role/*" } }
    }
  ]
}
POLICY
}

# Pattern built from a reference, known only at apply: 1 finding
data "aws_partition" "current" {}

resource "aws_s3_bucket" "partref" {
  bucket = "partref-bucket"
}

resource "aws_s3_bucket_policy" "partref" {
  bucket = aws_s3_bucket.partref.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::partref-bucket", "arn:aws:s3:::partref-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# Data source: the pattern sits beside another condition key: 1 finding
resource "aws_s3_bucket" "dsotherkey" {
  bucket = "dsotherkey-bucket"
}

data "aws_iam_policy_document" "dsotherkey" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::dsotherkey-bucket", "arn:aws:s3:::dsotherkey-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/aws-service-role/*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = ["123456789012"]
    }
  }
}

resource "aws_s3_bucket_policy" "dsotherkey" {
  bucket = aws_s3_bucket.dsotherkey.id
  policy = data.aws_iam_policy_document.dsotherkey.json
}

# Both forms together: the policy argument blocks every service-linked role,
# and the standalone policy exempts an unauthorized one: 1 finding
resource "aws_s3_bucket" "bothforms" {
  bucket = "bothforms-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::bothforms-bucket", "arn:aws:s3:::bothforms-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "bothforms" {
  bucket = aws_s3_bucket.bothforms.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::bothforms-bucket", "arn:aws:s3:::bothforms-bucket/*"],
      "Condition": {
        "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" },
        "StringNotEquals": { "aws:PrincipalArn": "arn:aws:iam::999999999999:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie" }
      }
    }
  ]
}
POLICY
}

# Both forms on one bucket with the Deny split between them (the policy
# argument reaches the bucket, the standalone policy the objects): only one
# applies after apply: 1 finding
resource "aws_s3_bucket" "splitpol" {
  bucket = "splitpol-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::splitpol-bucket",
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "splitpol" {
  bucket = aws_s3_bucket.splitpol.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::splitpol-bucket/*",
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# An account pattern that holds a digit misses other accounts: 1 finding
resource "aws_s3_bucket" "acctdigit" {
  bucket = "acctdigit-bucket"
}

resource "aws_s3_bucket_policy" "acctdigit" {
  bucket = aws_s3_bucket.acctdigit.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::acctdigit-bucket", "arn:aws:s3:::acctdigit-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*1*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}


# A partition outside aws, aws-cn and aws-us-gov: 1 finding
resource "aws_s3_bucket" "isopart" {
  bucket = "isopart-bucket"
}

resource "aws_s3_bucket_policy" "isopart" {
  bucket = aws_s3_bucket.isopart.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::isopart-bucket", "arn:aws:s3:::isopart-bucket/*"],
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws-iso:iam::*:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# Eleven "?" and no "*" match no account ID: 1 finding
resource "aws_s3_bucket" "acctelevenq" {
  bucket = "acctelevenq-bucket"
}

resource "aws_s3_bucket_policy" "acctelevenq" {
  bucket = aws_s3_bucket.acctelevenq.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::acctelevenq-bucket", "arn:aws:s3:::acctelevenq-bucket/*"],
      "Condition": { "StringLike": { "aws:PrincipalArn": "arn:aws:iam::???????????:role/aws-service-role/*" } }
    }
  ]
}
POLICY
}

# Like operator in lower case: operator names are case sensitive, so arnlike
# does not count as ArnLike and narrows the Deny: 1 finding
resource "aws_s3_bucket" "slroplowerjson" {
  bucket = "slroplowerjson-bucket"
}

resource "aws_s3_bucket_policy" "slroplowerjson" {
  bucket = aws_s3_bucket.slroplowerjson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::slroplowerjson-bucket",
        "arn:aws:s3:::slroplowerjson-bucket/*"
      ],
      "Condition": {
        "arnlike": { "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*" }
      }
    }
  ]
}
POLICY
}

# Like operator in lower case in a data source: 1 finding
resource "aws_s3_bucket" "slroplowerhcl" {
  bucket = "slroplowerhcl-bucket"
}

data "aws_iam_policy_document" "ds_slroplowerhcl" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.slroplowerhcl.arn, "${aws_s3_bucket.slroplowerhcl.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "stringlike"
      variable = "aws:PrincipalArn"
      values   = ["arn:*:iam::*:role/aws-service-role/*"]
    }
  }
}

resource "aws_s3_bucket_policy" "slroplowerhcl" {
  bucket = aws_s3_bucket.slroplowerhcl.id
  policy = data.aws_iam_policy_document.ds_slroplowerhcl.json
}

# Exemption operator in lower case beside a covering ArnLike: arnnotequals is
# not ArnNotEquals, so it narrows the Deny: 1 finding
resource "aws_s3_bucket" "slrexemptlower" {
  bucket = "slrexemptlower-bucket"
}

data "aws_iam_policy_document" "ds_slrexemptlower" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::slrexemptlower-bucket", "arn:aws:s3:::slrexemptlower-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/aws-service-role/*"]
    }

    condition {
      test     = "arnnotequals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"]
    }
  }
}

resource "aws_s3_bucket_policy" "slrexemptlower" {
  bucket = aws_s3_bucket.slrexemptlower.id
  policy = data.aws_iam_policy_document.ds_slrexemptlower.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket policy that is never created (count = 0) does not protect its bucket,
# even when it holds the required Deny.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "zz-slr-bucket"
}

data "aws_iam_policy_document" "zz_nc_doc" {
  statement {
    sid       = "DenyServiceLinkedRoles"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/aws-service-role/*"]
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
  bucket = "zz-slr-bucket"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "DenyServiceLinkedRoles"
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
    sid       = "DenyServiceLinkedRoles"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/aws-service-role/*"]
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
  bucket = "zz-slr-bucket"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
  statement {
    sid       = "DenyServiceLinkedRoles"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/aws-service-role/*"]
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
