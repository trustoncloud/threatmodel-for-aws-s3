# S3.C102 (cloudfront_association_check) - allowlist - VIOLATING

# OAC association to an unauthorized distribution: 1 finding
resource "aws_s3_bucket" "rogue_oac" {
  bucket = "rogue-oac-bucket"
}

resource "aws_s3_bucket_policy" "rogue_oac" {
  bucket = aws_s3_bucket.rogue_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontOac",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E9ROGUE9999999"
        }
      }
    }
  ]
}
POLICY
}

# Legacy OAI association to an unauthorized identity: 1 finding
resource "aws_s3_bucket" "rogue_oai" {
  bucket = "rogue-oai-bucket"
}

resource "aws_s3_bucket_policy" "rogue_oai" {
  bucket = aws_s3_bucket.rogue_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontOai",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E9ROGUE9999999"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-oai-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy form, OAC to an unauthorized distribution: 1 finding
resource "aws_s3_bucket" "rogue_cf_ds" {
  bucket = "rogue-cf-ds-bucket"
}

data "aws_iam_policy_document" "rogue_cf_ds" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::rogue-cf-ds-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E8ROGUEDS8888888"]
    }
  }
}

resource "aws_s3_bucket_policy" "rogue_cf_ds" {
  bucket = aws_s3_bucket.rogue_cf_ds.id
  policy = data.aws_iam_policy_document.rogue_cf_ds.json
}

# An approved distribution listed beside one that is not: 1 finding
resource "aws_s3_bucket" "mixed_oac" {
  bucket = "mixed-oac-bucket"
}

resource "aws_s3_bucket_policy" "mixed_oac" {
  bucket = aws_s3_bucket.mixed_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::mixed-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": [
            "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345",
            "arn:aws:cloudfront::123456789012:distribution/E9ROGUE9999999"
          ]
        }
      }
    }
  ]
}
POLICY
}

# A distribution ID that only starts with the approved ID: 1 finding
resource "aws_s3_bucket" "lookalike_oac" {
  bucket = "lookalike-oac-bucket"
}

resource "aws_s3_bucket_policy" "lookalike_oac" {
  bucket = aws_s3_bucket.lookalike_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::lookalike-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345X"
        }
      }
    }
  ]
}
POLICY
}

# A negated test admits every distribution but the approved one: 1 finding
resource "aws_s3_bucket" "negated_oac" {
  bucket = "negated-oac-bucket"
}

resource "aws_s3_bucket_policy" "negated_oac" {
  bucket = aws_s3_bucket.negated_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::negated-oac-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"
        }
      }
    }
  ]
}
POLICY
}

# A wildcard value is never approved: 1 finding
resource "aws_s3_bucket" "wildcard_oac" {
  bucket = "wildcard-oac-bucket"
}

resource "aws_s3_bucket_policy" "wildcard_oac" {
  bucket = aws_s3_bucket.wildcard_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::wildcard-oac-bucket/*",
      "Condition": {
        "ArnLike": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED*"
        }
      }
    }
  ]
}
POLICY
}

# The CloudFront service with no aws:SourceArn test: 1 finding
resource "aws_s3_bucket" "nocond_oac" {
  bucket = "nocond-oac-bucket"
}

resource "aws_s3_bucket_policy" "nocond_oac" {
  bucket = aws_s3_bucket.nocond_oac.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::nocond-oac-bucket/*"
    }
  ]
}
POLICY
}

# An approved identity listed beside one that is not: 1 finding
resource "aws_s3_bucket" "mixed_oai" {
  bucket = "mixed-oai-bucket"
}

resource "aws_s3_bucket_policy" "mixed_oai" {
  bucket = aws_s3_bucket.mixed_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2AUTHORIZED12345",
          "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2AUTHORIZED12345X"
        ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::mixed-oai-bucket/*"
    }
  ]
}
POLICY
}

# An identity created in the same configuration is not resolved by this source scan, so it
# cannot be approved: 1 finding
resource "aws_cloudfront_origin_access_identity" "legacy" {
  comment = "legacy identity"
}

resource "aws_s3_bucket" "created_oai" {
  bucket = "created-oai-bucket"
}

resource "aws_s3_bucket_policy" "created_oai" {
  bucket = aws_s3_bucket.created_oai.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "${aws_cloudfront_origin_access_identity.legacy.iam_arn}" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::created-oai-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy form, an approved distribution beside one that is not,
# under an implicit Allow: 1 finding
resource "aws_s3_bucket" "ds_mixed_cf" {
  bucket = "ds-mixed-cf-bucket"
}

data "aws_iam_policy_document" "ds_mixed_cf" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-mixed-cf-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345",
        "arn:aws:cloudfront::123456789012:distribution/E7ROGUEDS7777777",
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_mixed_cf" {
  bucket = aws_s3_bucket.ds_mixed_cf.id
  policy = data.aws_iam_policy_document.ds_mixed_cf.json
}

# Data-source policy form, a negated test on the approved distribution: 1 finding
resource "aws_s3_bucket" "ds_negated_cf" {
  bucket = "ds-negated-cf-bucket"
}

data "aws_iam_policy_document" "ds_negated_cf" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-negated-cf-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_negated_cf" {
  bucket = aws_s3_bucket.ds_negated_cf.id
  policy = data.aws_iam_policy_document.ds_negated_cf.json
}

# OAC association to an unauthorized distribution, set in the policy argument
# of the bucket: 1 finding
resource "aws_s3_bucket" "inline_rogue_oac" {
  bucket = "inline-rogue-oac-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::inline-rogue-oac-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E6ROGUEINLINE666"
        }
      }
    }
  ]
}
POLICY
}

# Unauthorized identity in the policy argument of the bucket built by a data
# source: 1 finding
resource "aws_s3_bucket" "inline_rogue_oai" {
  bucket = "inline-rogue-oai-bucket"
  policy = data.aws_iam_policy_document.inline_rogue_oai.json
}

data "aws_iam_policy_document" "inline_rogue_oai" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::inline-rogue-oai-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E5ROGUEINLINE555"]
    }
  }
}

# Both forms: the linked aws_s3_bucket_policy is approved, the policy argument
# grants the CloudFront service with no aws:SourceArn test: 1 finding
resource "aws_s3_bucket" "both_rogue_cf" {
  bucket = "both-rogue-cf-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::both-rogue-cf-bucket/*"
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "both_rogue_cf" {
  bucket = aws_s3_bucket.both_rogue_cf.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::both-rogue-cf-bucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"
        }
      }
    }
  ]
}
POLICY
}

# Data-source policy referenced through minified_json, OAC to an unauthorized
# distribution: 1 finding
resource "aws_s3_bucket" "ds_minified_cf" {
  bucket = "ds-minified-cf-bucket"
}

data "aws_iam_policy_document" "ds_minified_cf" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ds-minified-cf-bucket/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E7ROGUEMIN777777"]
    }
  }
}

resource "aws_s3_bucket_policy" "ds_minified_cf" {
  bucket = aws_s3_bucket.ds_minified_cf.id
  policy = data.aws_iam_policy_document.ds_minified_cf.minified_json
}

# --- Never-created resources and statements the source does not show ---

# A count other than 0 creates the bucket, so it is judged.
resource "aws_s3_bucket" "zzcounted" {
  count  = 1
  bucket = "zz-cloudfront-bucket"
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "s3:GetObject", "Resource": "*"}]}
POLICY
}

# A dynamic statement block generates statements the source does not show,
# which may grant more than the written statements.
resource "aws_s3_bucket" "zzdynadd" {
  bucket = "zz-cloudfront-bucket"
}

data "aws_iam_policy_document" "zz_dyn_added" {
  statement {
    sid       = "ApprovedDistribution"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }

  dynamic "statement" {
    for_each = ["s3:GetObject"]
    content {
      effect    = "Allow"
      actions   = [statement.value]
      resources = ["*"]
      principals {
        type        = "Service"
        identifiers = ["cloudfront.amazonaws.com"]
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
  bucket = "zz-cloudfront-bucket"
}

data "aws_iam_policy_document" "zz_src_extra" {
  statement {
    sid       = "ReadObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "zz_src_added" {
  source_policy_documents = [data.aws_iam_policy_document.zz_src_extra.json]

  statement {
    sid       = "ApprovedDistribution"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }
}

resource "aws_s3_bucket_policy" "zzsrcadd" {
  bucket = aws_s3_bucket.zzsrcadd.id
  policy = data.aws_iam_policy_document.zz_src_added.json
}

# A dynamic principals block generates principals the source does not show.
resource "aws_s3_bucket" "zzdynprinc" {
  bucket = "zz-cloudfront-bucket"
}

data "aws_iam_policy_document" "zz_dyn_principals" {
  statement {
    sid       = "ApprovedDistribution"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudfront::123456789012:distribution/E2AUTHORIZED12345"]
    }
  }

  statement {
    sid       = "GeneratedPrincipals"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    dynamic "principals" {
      for_each = ["Service"]
      content {
        type        = principals.value
        identifiers = ["cloudfront.amazonaws.com"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "zzdynprinc" {
  bucket = aws_s3_bucket.zzdynprinc.id
  policy = data.aws_iam_policy_document.zz_dyn_principals.json
}
