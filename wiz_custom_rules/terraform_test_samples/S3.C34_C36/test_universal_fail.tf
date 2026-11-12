# S3.C36 (vpc_endpoint_block_public_acl) - universal - VIOLATING

# S3 endpoint that does not block public object ACLs: 1 finding
resource "aws_vpc_endpoint" "s3_nolock" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*" }
  ]
}
POLICY
}

# --- Scope, operator and lookalike cases ---

# StringNotEquals denies every ACL except the public ones: 1 finding
resource "aws_vpc_endpoint" "notequalsop" {
  vpc_id            = "vpc-0126"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Only one of the two public canned ACLs is denied: 1 finding
resource "aws_vpc_endpoint" "onevalue" {
  vpc_id            = "vpc-0127"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Deny applies to one role only: 1 finding
resource "aws_vpc_endpoint" "onerole" {
  vpc_id            = "vpc-0128"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/app"
      },
      "Action": "s3:PutObjectAcl",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Deny names s3:PutObject only; setting an ACL, on upload or later, needs s3:PutObjectAcl: 1 finding
resource "aws_vpc_endpoint" "uploadonly" {
  vpc_id            = "vpc-0129"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Deny reaches one bucket only: 1 finding
resource "aws_vpc_endpoint" "onebkt" {
  vpc_id            = "vpc-012a"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "Resource": "arn:aws:s3:::one-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Deny on a pattern that only matches names starting with "s": 1 finding
resource "aws_vpc_endpoint" "prefixlook" {
  vpc_id            = "vpc-012b"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "Resource": "arn:aws:s3:::s*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Deny narrowed by a second condition: 1 finding
resource "aws_vpc_endpoint" "extracond" {
  vpc_id            = "vpc-012c"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        },
        "StringNotEquals": {
          "aws:PrincipalAccount": "111122223333"
        }
      }
    }
  ]
}
POLICY
}

# Deny written with NotResource: 1 finding
resource "aws_vpc_endpoint" "notres" {
  vpc_id            = "vpc-012d"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "NotResource": "arn:aws:s3:::website-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Data-source deny of one public canned ACL only: 1 finding
resource "aws_vpc_endpoint" "docone" {
  vpc_id            = "vpc-012e"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_onevalue.json
}

data "aws_iam_policy_document" "pd_onevalue" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["public-read-write"]
    }
  }
}

# Data-source deny under StringNotEquals: 1 finding
resource "aws_vpc_endpoint" "docnoteq" {
  vpc_id            = "vpc-012f"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_notequals.json
}

data "aws_iam_policy_document" "pd_notequals" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-acl"
      values   = ["public-read", "public-read-write"]
    }
  }
}
