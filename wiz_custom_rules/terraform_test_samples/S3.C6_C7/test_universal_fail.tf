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

# The bucket's own policy argument holds the transport Deny but no TLS
# floor: 1 finding (TLS)
resource "aws_s3_bucket" "inline_transport_only" {
  bucket = "inline-transport-only-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::inline-transport-only-bucket", "arn:aws:s3:::inline-transport-only-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

# Service exemption set to true, which leaves every other principal out of the
# transport Deny: 1 finding (transport)
resource "aws_s3_bucket" "exempt_true" {
  bucket = "exempt-true-bucket"
}

resource "aws_s3_bucket_policy" "exempt_true" {
  bucket = aws_s3_bucket.exempt_true.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::exempt-true-bucket", "arn:aws:s3:::exempt-true-bucket/*"],
      "Condition": { "BoolIfExists": { "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "true" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::exempt-true-bucket", "arn:aws:s3:::exempt-true-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Service exemption beside a second extra key, which narrows the TLS Deny:
# 1 finding (TLS)
resource "aws_s3_bucket" "exempt_extra" {
  bucket = "exempt-extra-bucket"
}

resource "aws_s3_bucket_policy" "exempt_extra" {
  bucket = aws_s3_bucket.exempt_extra.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::exempt-extra-bucket", "arn:aws:s3:::exempt-extra-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOldTlsOutsideAccount",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::exempt-extra-bucket", "arn:aws:s3:::exempt-extra-bucket/*"],
      "Condition": {
        "NumericLessThan": { "s3:TlsVersion": "1.2" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" },
        "StringNotEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}

# Unrelated operators: the transport key under StringEquals and the TLS key
# under a lower-case operator name: 2 findings
resource "aws_s3_bucket" "wrong_operator" {
  bucket = "wrong-operator-bucket"
}

data "aws_iam_policy_document" "ds_wrong_operator" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::wrong-operator-bucket", "arn:aws:s3:::wrong-operator-bucket/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::wrong-operator-bucket", "arn:aws:s3:::wrong-operator-bucket/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "numericlessthan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "wrong_operator" {
  bucket = aws_s3_bucket.wrong_operator.id
  policy = data.aws_iam_policy_document.ds_wrong_operator.json
}

# The Denies split across the bucket's own policy argument and an
# aws_s3_bucket_policy. Each writes the whole bucket policy and only one holds
# after apply, so each must carry both Denies: 2 findings
resource "aws_s3_bucket" "split_forms" {
  bucket = "split-forms-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::split-forms-bucket", "arn:aws:s3:::split-forms-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "split_forms" {
  bucket = aws_s3_bucket.split_forms.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::split-forms-bucket", "arn:aws:s3:::split-forms-bucket/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Service exemption under plain Bool: anonymous requests omit
# aws:PrincipalIsAWSService, so the condition is false for them and an
# unsigned HTTP request is not denied: 2 findings
resource "aws_s3_bucket" "exempt_plain_bool" {
  bucket = "exempt-plain-bool-bucket"
}

resource "aws_s3_bucket_policy" "exempt_plain_bool" {
  bucket = aws_s3_bucket.exempt_plain_bool.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::exempt-plain-bool-bucket", "arn:aws:s3:::exempt-plain-bool-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false" } }
    },
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::exempt-plain-bool-bucket", "arn:aws:s3:::exempt-plain-bool-bucket/*"],
      "Condition": {
        "NumericLessThan": { "s3:TlsVersion": "1.2" },
        "Bool": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
POLICY
}

# --- Never-created resources and statements the source does not show ---

# A bucket policy that is never created (count = 0) does not protect its bucket,
# even when it holds the required Deny.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "zz-transport-bucket"
}

data "aws_iam_policy_document" "zz_nc_doc" {
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

resource "aws_s3_bucket_policy" "zzncpol" {
  count  = 0
  bucket = aws_s3_bucket.zzncpol.id
  policy = data.aws_iam_policy_document.zz_nc_doc.json
}

# override_policy_documents replaces any written statement with the same
# sid, so a document that sets it cannot prove the Deny.
resource "aws_s3_bucket" "zzoverride" {
  bucket = "zz-transport-bucket"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "DenyOldTls"
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

resource "aws_s3_bucket_policy" "zzoverride" {
  bucket = aws_s3_bucket.zzoverride.id
  policy = data.aws_iam_policy_document.zz_overridden.json
}

# A dynamic condition block adds conditions the source does not show, which
# can narrow the Deny, so that statement does not count.
resource "aws_s3_bucket" "zzdyncond" {
  bucket = "zz-transport-bucket"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
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
