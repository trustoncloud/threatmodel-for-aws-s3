# S3.C147 (bucket_enforce_ssec) - allowlist - VIOLATING

# Required bucket with a policy that does not enforce SSE-C: 1 finding
resource "aws_s3_bucket" "ssec_required" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssec_required" {
  bucket = aws_s3_bucket.ssec_required.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*"
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/ but the deny covers another path: 1 finding
resource "aws_s3_bucket" "mixedfail" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixedfail" {
  bucket = aws_s3_bucket.mixedfail.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/tmp/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Whole-bucket entry enforced for one role only: 1 finding
resource "aws_s3_bucket" "ssecrole" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecrole" {
  bucket = aws_s3_bucket.ssecrole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Whole-bucket entry narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "ssecextra" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecextra" {
  bucket = aws_s3_bucket.ssecextra.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}

# Whole-bucket entry, object pattern leaves keys out (literal ARN): 1 finding
resource "aws_s3_bucket" "ssecnarrow" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecnarrow" {
  bucket = aws_s3_bucket.ssecnarrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/s*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/, pattern leaves keys of the path out (reference): 1 finding
resource "aws_s3_bucket" "mixednarrow" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixednarrow" {
  bucket = aws_s3_bucket.mixednarrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": ["${aws_s3_bucket.mixednarrow.arn}/secure/s*", "${aws_s3_bucket.mixednarrow.arn}/secure/sample-object"],
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Deny written with NotResource is never counted: 1 finding
resource "aws_s3_bucket" "ssecnot" {
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "ssecnot" {
  statement {
    effect  = "Deny"
    actions = ["s3:PutObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_resources = ["arn:aws:s3:::ssec-required-bucket/public/*"]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["true"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssecnot" {
  bucket = aws_s3_bucket.ssecnot.id
  policy = data.aws_iam_policy_document.ssecnot.json
}

# Path entry mixed-bucket/secure/ with "secure/?*", which misses the key "secure/" itself: 1 finding
resource "aws_s3_bucket" "mixednonempty" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixednonempty" {
  bucket = aws_s3_bucket.mixednonempty.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/secure/?*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Required bucket whose policy argument tests another header: 1 finding
resource "aws_s3_bucket" "inline_ssec_other" {
  bucket = "ssec-required-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption": "AES256" }
      }
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/, the policy argument covers another path: 1 finding
resource "aws_s3_bucket" "inline_mixed_other" {
  bucket = "mixed-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/secure-old/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Both forms, neither enough: the policy argument covers one role, the linked
# aws_s3_bucket_policy a lower-case action that is not PutObject: 1 finding
resource "aws_s3_bucket" "both_ssec_partial" {
  bucket = "ssec-required-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:putobject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_ssec_partial" {
  bucket = aws_s3_bucket.both_ssec_partial.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:putobjectacl",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Both forms, requirement in one only: the linked aws_s3_bucket_policy holds
# the Deny, the policy argument holds another statement, and only one applies
# after apply: 1 finding
resource "aws_s3_bucket" "split_ssec" {
  bucket = "ssec-required-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/reader" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*"
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "split_ssec" {
  bucket = aws_s3_bucket.split_ssec.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Condition operator in lower case: operator names are case sensitive, so null
# does not count as Null: 1 finding
resource "aws_s3_bucket" "ssecoplowerjson" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecoplowerjson" {
  bucket = aws_s3_bucket.ssecoplowerjson.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Condition operator in lower case in a data source: 1 finding
resource "aws_s3_bucket" "ssecoplowerhcl" {
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "ds_ssecoplowerhcl" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.ssecoplowerhcl.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "stringnotequals"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["AES256"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssecoplowerhcl" {
  bucket = aws_s3_bucket.ssecoplowerhcl.id
  policy = data.aws_iam_policy_document.ds_ssecoplowerhcl.json
}

# Action patterns that leave PutObject out: s3:Get* and s3:PutObjectAcl: 1 finding
resource "aws_s3_bucket" "ssecactget" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecactget" {
  bucket = aws_s3_bucket.ssecactget.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:Get*", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Action pattern s3:PutObject? needs one more character, so it leaves
# PutObject out (data source): 1 finding
resource "aws_s3_bucket" "ssecactqmark" {
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "ds_ssecactqmark" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObject?"]
    resources = ["${aws_s3_bucket.ssecactqmark.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["true"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssecactqmark" {
  bucket = aws_s3_bucket.ssecactqmark.id
  policy = data.aws_iam_policy_document.ds_ssecactqmark.json
}

# --- Never-created resources and statements the source does not show ---

# A bucket policy that is never created (count = 0) does not protect its bucket,
# even when it holds the required Deny.
resource "aws_s3_bucket" "zzncpol" {
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "zz_nc_doc" {
  statement {
    sid       = "RequireSsec"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["AES256"]
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
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "RequireSsec"
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
    sid       = "RequireSsec"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["AES256"]
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
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
  statement {
    sid       = "RequireSsec"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["AES256"]
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
