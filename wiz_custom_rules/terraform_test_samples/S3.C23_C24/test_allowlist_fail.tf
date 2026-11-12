# S3.C24 (vpc_endpoint_bucket_restriction) - allowlist - VIOLATING

# S3 endpoint with no policy (default full access): 1 finding
resource "aws_vpc_endpoint" "s3_nopol" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

# S3 endpoint allowing an unauthorized bucket: 1 finding
resource "aws_vpc_endpoint" "s3_roguebkt" {
  vpc_id            = "vpc-0ddd"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy with an omitted effect (defaults to Allow) granting an
# unauthorized bucket: 1 finding
resource "aws_vpc_endpoint" "ep_bad_doc" {
  vpc_id            = "vpc-0eee"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_bad_bucket_doc.json
}

data "aws_iam_policy_document" "pol_bad_bucket_doc" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::rogue-doc-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# --- Scope, operator and lookalike cases ---

# Allow written with NotResource, which grants every other bucket: 1 finding
resource "aws_vpc_endpoint" "notres" {
  vpc_id            = "vpc-011e"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "NotResource": "arn:aws:s3:::blocked-bucket/*"
    }
  ]
}
POLICY
}

# Data-source Allow (effect omitted) written with not_resources: 1 finding
resource "aws_vpc_endpoint" "docexclude" {
  vpc_id            = "vpc-011f"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_notresources.json
}

data "aws_iam_policy_document" "pd_notresources" {
  statement {
    actions   = ["s3:GetObject"]
    not_resources = ["arn:aws:s3:::blocked-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Wildcard at the end of the authorized bucket name reaches other buckets: 1 finding
resource "aws_vpc_endpoint" "wildbkt" {
  vpc_id            = "vpc-0120"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::authorized-bucket*"
    }
  ]
}
POLICY
}

# A bucket whose name only starts with the authorized one: 1 finding
resource "aws_vpc_endpoint" "bktlook" {
  vpc_id            = "vpc-0121"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::authorized-bucket-rogue/*"
    }
  ]
}
POLICY
}

# Every bucket: 1 finding
resource "aws_vpc_endpoint" "allbkts" {
  vpc_id            = "vpc-0122"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
POLICY
}

# The authorized bucket name in another partition: 1 finding
resource "aws_vpc_endpoint" "otherpart" {
  vpc_id            = "vpc-0123"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws-cn:s3:::authorized-bucket/*"
    }
  ]
}
POLICY
}

# --- References to buckets in this file ---

# Bucket with a generated name (bucket_prefix), referenced by ARN: 1 finding
resource "aws_s3_bucket" "authorized-bucket" {
  bucket_prefix = "authorized-bucket"
}

resource "aws_vpc_endpoint" "refprefix" {
  vpc_id            = "vpc-0310"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "${aws_s3_bucket.authorized-bucket.arn}/*"
    }
  ]
}
POLICY
}

# Bucket that states no name at all, referenced by id: 1 finding
resource "aws_s3_bucket" "unnamed" {
}

resource "aws_vpc_endpoint" "refunnamed" {
  vpc_id            = "vpc-0311"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_ref_unnamed.json
}

data "aws_iam_policy_document" "pd_ref_unnamed" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.unnamed.id}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Bucket with a literal name outside the allowlist: 1 finding
resource "aws_s3_bucket" "other" {
  bucket = "authorized-bucket-copy"
}

resource "aws_vpc_endpoint" "refother" {
  vpc_id            = "vpc-0312"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_ref_other.json
}

data "aws_iam_policy_document" "pd_ref_other" {
  statement {
    actions   = ["s3:GetObject"]
    resources = [aws_s3_bucket.other.arn, "${aws_s3_bucket.other.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Bucket whose name comes from a variable: 1 finding
variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "fromvar" {
  bucket = var.bucket_name
}

resource "aws_vpc_endpoint" "reffromvar" {
  vpc_id            = "vpc-0313"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "${aws_s3_bucket.fromvar.arn}/*"
    }
  ]
}
POLICY
}

# Bucket created several times (count), referenced by index: 1 finding
resource "aws_s3_bucket" "counted" {
  count  = 2
  bucket = "authorized-bucket"
}

resource "aws_vpc_endpoint" "refcounted" {
  vpc_id            = "vpc-0314"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "${aws_s3_bucket.counted[0].arn}/*"
    }
  ]
}
POLICY
}

# Authorized bucket next to a second reference in one value: 1 finding
resource "aws_s3_bucket" "named_ok" {
  bucket = "authorized-bucket"
}

resource "aws_vpc_endpoint" "reftwo" {
  vpc_id            = "vpc-0316"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${aws_s3_bucket.named_ok.id}${var.bucket_name}/*"
    }
  ]
}
POLICY
}

# --- The partition of an ARN reference is the endpoint's partition ---

# China endpoint: the referenced bucket is arn:aws-cn:s3:::authorized-bucket, not on the list: 1 finding
resource "aws_vpc_endpoint" "refarncn" {
  vpc_id            = "vpc-0317"
  service_name      = "cn.com.amazonaws.cn-north-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_ref_cn.json
}

data "aws_iam_policy_document" "pd_ref_cn" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.named_ok.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# GovCloud endpoint: the referenced bucket is arn:aws-us-gov:s3:::authorized-bucket, not on the list: 1 finding
resource "aws_vpc_endpoint" "refarngov" {
  vpc_id            = "vpc-0318"
  service_name      = "com.amazonaws.us-gov-west-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_ref_gov.json
}

data "aws_iam_policy_document" "pd_ref_gov" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.named_ok.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Endpoint in a region whose partition this rule does not know: not resolved, 1 finding
resource "aws_vpc_endpoint" "refarniso" {
  vpc_id            = "vpc-0319"
  service_name      = "com.amazonaws.us-iso-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_ref_iso.json
}

data "aws_iam_policy_document" "pd_ref_iso" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.named_ok.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
