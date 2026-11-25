# S3.C67 (bucket_enforce_kms_key) - allowlist - VIOLATING

# Bucket with no bucket policy: 1 finding
resource "aws_s3_bucket" "no_policy" {
  bucket = "no-policy-bucket"
}

# Bucket whose deny permits an unauthorized KMS key: 1 finding
resource "aws_s3_bucket" "rogue_key" {
  bucket = "rogue-key-bucket"
}

resource "aws_s3_bucket_policy" "rogue_key" {
  bucket = aws_s3_bucket.rogue_key.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthorizedKmsKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::rogue-key-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:999999999999:key/rogue-key"
        }
      }
    }
  ]
}
POLICY
}

# Key enforcement applies to one role only: 1 finding
resource "aws_s3_bucket" "key_onerole" {
  bucket = "key-onerole-bucket"
}

resource "aws_s3_bucket_policy" "key_onerole" {
  bucket = aws_s3_bucket.key_onerole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-onerole-bucket/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    }
  ]
}
POLICY
}

# Key enforcement reaches one prefix only: 1 finding
resource "aws_s3_bucket" "key_prefix" {
  bucket = "key-prefix-bucket"
}

resource "aws_s3_bucket_policy" "key_prefix" {
  bucket = aws_s3_bucket.key_prefix.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-prefix-bucket/uploads/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    }
  ]
}
POLICY
}

# Key enforcement narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "key_extracond" {
  bucket = "key-extracond-bucket"
}

resource "aws_s3_bucket_policy" "key_extracond" {
  bucket = aws_s3_bucket.key_extracond.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-extracond-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}

# Object pattern leaves keys out (literal ARN): 1 finding
resource "aws_s3_bucket" "key_narrow" {
  bucket = "key-narrow-bucket"
}

resource "aws_s3_bucket_policy" "key_narrow" {
  bucket = aws_s3_bucket.key_narrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::key-narrow-bucket/s*",
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

# One object named in place of every object (reference to the bucket ARN): 1 finding
resource "aws_s3_bucket" "key_oneobject" {
  bucket = "key-oneobject-bucket"
}

resource "aws_s3_bucket_policy" "key_oneobject" {
  bucket = aws_s3_bucket.key_oneobject.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.key_oneobject.arn}/sample-object",
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

# Deny written with NotResource is never counted: 1 finding
resource "aws_s3_bucket" "key_notresource" {
  bucket = "key-notresource-bucket"
}

data "aws_iam_policy_document" "key_notresource" {
  statement {
    effect  = "Deny"
    actions = ["s3:PutObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_resources = ["arn:aws:s3:::key-notresource-bucket/public/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

resource "aws_s3_bucket_policy" "key_notresource" {
  bucket = aws_s3_bucket.key_notresource.id
  policy = data.aws_iam_policy_document.key_notresource.json
}

# Policy argument of the bucket permits an unauthorized KMS key: 1 finding
resource "aws_s3_bucket" "inline_rogue" {
  bucket = "inline-rogue-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::inline-rogue-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:999999999999:key/rogue-key"
        }
      }
    }
  ]
}
POLICY
}

# Policy argument of the bucket denies uploads to another bucket only: 1 finding
resource "aws_s3_bucket" "inline_other" {
  bucket = "inline-other-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::inline-other-bucket-rogue/*",
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

# Both forms, neither enough: the policy argument covers one role, the linked
# aws_s3_bucket_policy one prefix, and a lower-case action that is not
# PutObject: 1 finding
resource "aws_s3_bucket" "both_partial" {
  bucket = "both-partial-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:putobject",
      "Resource": "arn:aws:s3:::both-partial-bucket/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:putobjectacl",
      "Resource": "arn:aws:s3:::both-partial-bucket/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_partial" {
  bucket = aws_s3_bucket.both_partial.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::both-partial-bucket/uploads/*",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key" } }
    }
  ]
}
POLICY
}

# Both forms, requirement in one only: the policy argument holds the Deny, the
# linked aws_s3_bucket_policy holds another statement, and only one applies
# after apply: 1 finding
resource "aws_s3_bucket" "split_key" {
  bucket = "split-key-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::split-key-bucket/*",
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

resource "aws_s3_bucket_policy" "split_key" {
  bucket = aws_s3_bucket.split_key.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/reader" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::split-key-bucket/*"
    }
  ]
}
POLICY
}

# Condition operator in lower case: operator names are case sensitive, so
# stringnotequals does not count as StringNotEquals: 1 finding
resource "aws_s3_bucket" "oplowerjson" {
  bucket = "oplowerjson-bucket"
}

resource "aws_s3_bucket_policy" "oplowerjson" {
  bucket = aws_s3_bucket.oplowerjson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::oplowerjson-bucket/*",
      "Condition": {
        "stringnotequals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
        }
      }
    }
  ]
}
POLICY
}

# Condition operator in lower case in a data source: 1 finding
resource "aws_s3_bucket" "oplowerhcl" {
  bucket = "oplowerhcl-bucket"
}

data "aws_iam_policy_document" "ds_oplowerhcl" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.oplowerhcl.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "stringnotequals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

resource "aws_s3_bucket_policy" "oplowerhcl" {
  bucket = aws_s3_bucket.oplowerhcl.id
  policy = data.aws_iam_policy_document.ds_oplowerhcl.json
}

# Action patterns that leave PutObject out: s3:Get* and s3:PutObjectAcl: 1 finding
resource "aws_s3_bucket" "actget" {
  bucket = "actget-bucket"
}

resource "aws_s3_bucket_policy" "actget" {
  bucket = aws_s3_bucket.actget.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:Get*", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::actget-bucket/*",
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

# Action pattern s3:PutObject? needs one more character, so it leaves
# PutObject out (data source): 1 finding
resource "aws_s3_bucket" "actqmark" {
  bucket = "actqmark-bucket"
}

data "aws_iam_policy_document" "ds_actqmark" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObject?"]
    resources = ["${aws_s3_bucket.actqmark.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
    }
  }
}

resource "aws_s3_bucket_policy" "actqmark" {
  bucket = aws_s3_bucket.actqmark.id
  policy = data.aws_iam_policy_document.ds_actqmark.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket policy that is never created (count = 0) does not protect its bucket,
# even when it holds the required Deny.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "zz-kms-bucket"
}

data "aws_iam_policy_document" "zz_nc_doc" {
  statement {
    sid       = "RequireAuthorizedKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
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
  bucket = "zz-kms-bucket"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "RequireAuthorizedKey"
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
    sid       = "RequireAuthorizedKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
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
  bucket = "zz-kms-bucket"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
  statement {
    sid       = "RequireAuthorizedKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["arn:aws:kms:us-east-1:123456789012:key/authorized-key"]
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
