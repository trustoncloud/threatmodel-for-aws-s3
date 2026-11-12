# S3.C24 (vpc_endpoint_bucket_restriction) - allowlist - COMPLIANT (0 findings)

resource "aws_vpc_endpoint" "s3_scoped" {
  vpc_id            = "vpc-0aaa"
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
      "Resource": [
        "arn:aws:s3:::authorized-bucket",
        "arn:aws:s3:::authorized-bucket/*"
      ]
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "kms_ep" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.kms"
  vpc_endpoint_type = "Interface"
}

# Allow scoped to the authorized bucket, from a policy-document data source
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_bucket_doc.json
}

data "aws_iam_policy_document" "pol_bucket_doc" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::authorized-bucket",
      "arn:aws:s3:::authorized-bucket/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# --- Scope, operator and lookalike cases ---

# Objects under a key prefix of the authorized bucket, and a Deny written
# with NotResource, which grants nothing
resource "aws_vpc_endpoint" "keyprefix" {
  vpc_id            = "vpc-0124"
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
      "Resource": [
        "arn:aws:s3:::authorized-bucket/logs/*",
        "arn:aws:s3:::authorized-bucket/config.json"
      ]
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "NotResource": [
        "arn:aws:s3:::authorized-bucket",
        "arn:aws:s3:::authorized-bucket/*"
      ]
    }
  ]
}
POLICY
}

# Data-source Allow (effect omitted) attached via the standalone endpoint-policy resource
resource "aws_vpc_endpoint" "docassoc" {
  vpc_id            = "vpc-0125"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "docassoc" {
  vpc_endpoint_id = aws_vpc_endpoint.docassoc.id
  policy          = data.aws_iam_policy_document.pd_bucketassoc.json
}

data "aws_iam_policy_document" "pd_bucketassoc" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::authorized-bucket", "arn:aws:s3:::authorized-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# --- References to buckets in this file that state a literal name ---

resource "aws_s3_bucket" "approved" {
  bucket = "authorized-bucket"
}

data "aws_s3_bucket" "approved_lookup" {
  bucket = "authorized-bucket"
}

# By ARN, in a heredoc policy
resource "aws_vpc_endpoint" "refarn" {
  vpc_id            = "vpc-0320"
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
      "Resource": [
        "${aws_s3_bucket.approved.arn}",
        "${aws_s3_bucket.approved.arn}/*"
      ]
    }
  ]
}
POLICY
}

# By id and bucket, and through a data source, in a policy-document data source
resource "aws_vpc_endpoint" "refid" {
  vpc_id            = "vpc-0321"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_ref_approved.json
}

data "aws_iam_policy_document" "pd_ref_approved" {
  statement {
    actions = ["s3:GetObject"]
    resources = [
      aws_s3_bucket.approved.arn,
      "arn:aws:s3:::${aws_s3_bucket.approved.id}/*",
      "arn:aws:s3:::${aws_s3_bucket.approved.bucket}/reports/*",
      "${data.aws_s3_bucket.approved_lookup.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
