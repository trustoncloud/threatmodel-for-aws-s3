# S3.C100 (bucket_vpc_restriction) - allowlist - VIOLATING

# No VPC restriction (no policy): 1 finding
resource "aws_s3_bucket" "no_restriction" {
  bucket = "no-restriction-bucket"
}

# Restriction allows an unauthorized VPC: 1 finding
resource "aws_s3_bucket" "rogue_vpc" {
  bucket = "rogue-vpc-bucket"
}

resource "aws_s3_bucket_policy" "rogue_vpc" {
  bucket = aws_s3_bucket.rogue_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExceptVpc",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::rogue-vpc-bucket", "arn:aws:s3:::rogue-vpc-bucket/*"],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-99999999999999999" }
      }
    }
  ]
}
POLICY
}

# Data-source policy form, restriction allows an unauthorized VPC: 1 finding
resource "aws_s3_bucket" "ds_unauth_vpc" {
  bucket = "rogue-vpc-ds-bucket"
}

data "aws_iam_policy_document" "ds_unauth_vpc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::rogue-vpc-ds-bucket", "arn:aws:s3:::rogue-vpc-ds-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-88888888888888888"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_unauth_vpc" {
  bucket = aws_s3_bucket.ds_unauth_vpc.id
  policy = data.aws_iam_policy_document.ds_unauth_vpc.json
}

# Restriction applies to one role only: 1 finding
resource "aws_s3_bucket" "vpc_onerole" {
  bucket = "vpc-onerole-bucket"
}

resource "aws_s3_bucket_policy" "vpc_onerole" {
  bucket = aws_s3_bucket.vpc_onerole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vpc-onerole-bucket", "arn:aws:s3:::vpc-onerole-bucket/*"],
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Restriction covers a single action only: 1 finding
resource "aws_s3_bucket" "vpc_getonly" {
  bucket = "vpc-getonly-bucket"
}

resource "aws_s3_bucket_policy" "vpc_getonly" {
  bucket = aws_s3_bucket.vpc_getonly.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": ["arn:aws:s3:::vpc-getonly-bucket", "arn:aws:s3:::vpc-getonly-bucket/*"],
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Restriction reaches the objects only, bucket-level requests stay open: 1 finding
resource "aws_s3_bucket" "vpc_objonly" {
  bucket = "vpc-objonly-bucket"
}

resource "aws_s3_bucket_policy" "vpc_objonly" {
  bucket = aws_s3_bucket.vpc_objonly.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.vpc_objonly.arn}/*",
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Second key under the same operator widens access (either match is enough): 1 finding
resource "aws_s3_bucket" "vpc_extrakey" {
  bucket = "vpc-extrakey-bucket"
}

resource "aws_s3_bucket_policy" "vpc_extrakey" {
  bucket = aws_s3_bucket.vpc_extrakey.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vpc-extrakey-bucket", "arn:aws:s3:::vpc-extrakey-bucket/*"],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpc": "vpc-0123456789abcdef0",
          "aws:SourceVpce": "vpce-0123456789abcdef0"
        }
      }
    }
  ]
}
POLICY
}

# Object pattern leaves keys out (literal ARN): 1 finding
resource "aws_s3_bucket" "vpc_narrow" {
  bucket = "vpc-narrow-bucket"
}

resource "aws_s3_bucket_policy" "vpc_narrow" {
  bucket = aws_s3_bucket.vpc_narrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vpc-narrow-bucket", "arn:aws:s3:::vpc-narrow-bucket/s*"],
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# One object named in place of every object (reference to the bucket ARN): 1 finding
resource "aws_s3_bucket" "vpc_oneobject" {
  bucket = "vpc-oneobject-bucket"
}

resource "aws_s3_bucket_policy" "vpc_oneobject" {
  bucket = aws_s3_bucket.vpc_oneobject.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["${aws_s3_bucket.vpc_oneobject.arn}", "${aws_s3_bucket.vpc_oneobject.arn}/sample-object"],
      "Condition": { "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" } }
    }
  ]
}
POLICY
}

# Deny written with NotResource is never counted: 1 finding
resource "aws_s3_bucket" "vpc_notresource" {
  bucket = "vpc-notresource-bucket"
}

data "aws_iam_policy_document" "vpc_notresource" {
  statement {
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_resources = ["arn:aws:s3:::vpc-notresource-bucket/public/*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket_policy" "vpc_notresource" {
  bucket = aws_s3_bucket.vpc_notresource.id
  policy = data.aws_iam_policy_document.vpc_notresource.json
}

# Policy argument of the bucket allows an unauthorized VPC: 1 finding
resource "aws_s3_bucket" "inline_rogue_vpc" {
  bucket = "inline-rogue-vpc-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::inline-rogue-vpc-bucket",
        "arn:aws:s3:::inline-rogue-vpc-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-77777777777777777" }
      }
    }
  ]
}
POLICY
}

# Both forms: the linked aws_s3_bucket_policy is compliant, the policy
# argument allows an unauthorized VPC: 1 finding
resource "aws_s3_bucket" "both_bad_vpc" {
  bucket = "both-bad-vpc-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::both-bad-vpc-bucket",
        "arn:aws:s3:::both-bad-vpc-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-66666666666666666" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_bad_vpc" {
  bucket = aws_s3_bucket.both_bad_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::both-bad-vpc-bucket",
        "arn:aws:s3:::both-bad-vpc-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Policy argument of the bucket restricts one lower-case action only: 1 finding
resource "aws_s3_bucket" "inline_getonly" {
  bucket = "inline-getonly-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:getobject",
      "Resource": [
        "arn:aws:s3:::inline-getonly-bucket",
        "arn:aws:s3:::inline-getonly-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Both forms, requirement split: the policy argument reaches the bucket, the
# linked aws_s3_bucket_policy the objects, and only one applies after apply:
# 1 finding
resource "aws_s3_bucket" "split_vpc" {
  bucket = "split-vpc-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::split-vpc-bucket",
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "split_vpc" {
  bucket = aws_s3_bucket.split_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::split-vpc-bucket/*",
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Requirement split over two aws_s3_bucket_policy resources, of which only one
# applies after apply: 1 finding
resource "aws_s3_bucket" "split_two_vpc" {
  bucket = "split-two-vpc-bucket"
}

resource "aws_s3_bucket_policy" "split_two_vpc_bucket" {
  bucket = aws_s3_bucket.split_two_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::split-two-vpc-bucket",
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "split_two_vpc_objects" {
  bucket = aws_s3_bucket.split_two_vpc.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::split-two-vpc-bucket/*",
      "Condition": {
        "StringNotEquals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Condition operator in lower case: operator names are case sensitive, so
# stringnotequals does not count as StringNotEquals: 1 finding
resource "aws_s3_bucket" "vpcoplowerjson" {
  bucket = "vpcoplowerjson-bucket"
}

resource "aws_s3_bucket_policy" "vpcoplowerjson" {
  bucket = aws_s3_bucket.vpcoplowerjson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vpcoplowerjson-bucket", "arn:aws:s3:::vpcoplowerjson-bucket/*"],
      "Condition": {
        "stringnotequals": { "aws:SourceVpc": "vpc-0123456789abcdef0" }
      }
    }
  ]
}
POLICY
}

# Condition operator in upper case in a data source: 1 finding
resource "aws_s3_bucket" "vpcopupperhcl" {
  bucket = "vpcopupperhcl-bucket"
}

data "aws_iam_policy_document" "ds_vpcopupperhcl" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.vpcopupperhcl.arn, "${aws_s3_bucket.vpcopupperhcl.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "STRINGNOTEQUALSIFEXISTS"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket_policy" "vpcopupperhcl" {
  bucket = aws_s3_bucket.vpcopupperhcl.id
  policy = data.aws_iam_policy_document.ds_vpcopupperhcl.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket policy that is never created (count = 0) does not protect its bucket,
# even when it holds the required Deny.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "zz-vpc-bucket"
}

data "aws_iam_policy_document" "zz_nc_doc" {
  statement {
    sid       = "OnlyAuthorizedVpc"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
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
  bucket = "zz-vpc-bucket"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "OnlyAuthorizedVpc"
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
    sid       = "OnlyAuthorizedVpc"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
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
  bucket = "zz-vpc-bucket"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
  statement {
    sid       = "OnlyAuthorizedVpc"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"
      values   = ["vpc-0123456789abcdef0"]
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
