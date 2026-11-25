# S3.C36 (vpc_endpoint_block_public_acl) - universal - VIOLATING

# S3 endpoint with only the full-access policy: 1 finding
resource "aws_vpc_endpoint" "s3_nolock" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*" }
  ]
}
POLICY
}

# --- Scope, operator and lookalike cases ---
# Each policy below is complete except for the one defect named.

# StringNotEquals denies every canned ACL except the public ones: 1 finding
resource "aws_vpc_endpoint" "notequalsop" {
  vpc_id            = "vpc-0126"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringNotEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Only one of the public canned ACLs is denied: 1 finding
resource "aws_vpc_endpoint" "onevalue" {
  vpc_id            = "vpc-0127"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Every deny applies to one role only: 1 finding
resource "aws_vpc_endpoint" "onerole" {
  vpc_id            = "vpc-0128"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"}, "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"}, "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"}, "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"}, "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"}, "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Every deny names s3:PutObject only; setting an ACL, on upload or later, needs the ACL actions: 1 finding
resource "aws_vpc_endpoint" "uploadonly" {
  vpc_id            = "vpc-0129"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Every deny reaches one bucket only: 1 finding
resource "aws_vpc_endpoint" "onebkt" {
  vpc_id            = "vpc-012a"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::one-bucket/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::one-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::one-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::one-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::one-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Every deny is on a pattern that only matches names starting with "s": 1 finding
resource "aws_vpc_endpoint" "prefixlook" {
  vpc_id            = "vpc-012b"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::s*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::s*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::s*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::s*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::s*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# The canned ACL deny is narrowed by a second condition: 1 finding
resource "aws_vpc_endpoint" "extracond" {
  vpc_id            = "vpc-012c"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}, "StringNotEquals": {"aws:PrincipalAccount": "111122223333"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Every deny is written with NotResource: 1 finding
resource "aws_vpc_endpoint" "notres" {
  vpc_id            = "vpc-012d"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "NotResource": "arn:aws:s3:::website-bucket/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "NotResource": "arn:aws:s3:::website-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "NotResource": "arn:aws:s3:::website-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "NotResource": "arn:aws:s3:::website-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "NotResource": "arn:aws:s3:::website-bucket/*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Data-source deny of one public canned ACL only: 1 finding
resource "aws_vpc_endpoint" "docone" {
  vpc_id            = "vpc-012e"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_docone.json
}

data "aws_iam_policy_document" "pd_docone" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
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

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-write-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-full-control"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }
}

# Data-source canned ACL deny under StringNotEquals: 1 finding
resource "aws_vpc_endpoint" "docnoteq" {
  vpc_id            = "vpc-012f"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_docnoteq.json
}

data "aws_iam_policy_document" "pd_docnoteq" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-acl"
      values   = ["public-read", "public-read-write", "authenticated-read"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-write-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-full-control"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }
}

# --- Grant headers and object versions ---

# Canned ACLs denied for both actions, grant headers left open: 1 finding
resource "aws_vpc_endpoint" "cannedonly" {
  vpc_id            = "vpc-0140"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} }
  ]
}
POLICY
}

# Every header denied for s3:PutObjectAcl only, so version-specific ACL writes stay open: 1 finding
resource "aws_vpc_endpoint" "noversion" {
  vpc_id            = "vpc-0141"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# All four grant headers in one statement deny only requests that carry all four: 1 finding
resource "aws_vpc_endpoint" "grantsjoined" {
  vpc_id            = "vpc-0142"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"], "s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"], "s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"], "s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Grant headers matched as exact values, which a second grantee in the header escapes: 1 finding
resource "aws_vpc_endpoint" "grantexact" {
  vpc_id            = "vpc-0143"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-grant-read": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\""]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-grant-read-acp": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\""]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-grant-write-acp": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\""]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-grant-full-control": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\""]}} }
  ]
}
POLICY
}

# Grant patterns fixed at the start, so a header that names another grantee first escapes: 1 finding
resource "aws_vpc_endpoint" "grantanchored" {
  vpc_id            = "vpc-0144"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"*", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"*", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"*", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"*", "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"*"]}} }
  ]
}
POLICY
}

# Grant headers denied for AllUsers only: 1 finding
resource "aws_vpc_endpoint" "onegroup" {
  vpc_id            = "vpc-0146"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*"]}} }
  ]
}
POLICY
}

# Data-source deny with two grant headers as two condition blocks of one statement: 1 finding
resource "aws_vpc_endpoint" "docjoined" {
  vpc_id            = "vpc-0145"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_docjoined.json
}

data "aws_iam_policy_document" "pd_docjoined" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["public-read", "public-read-write", "authenticated-read"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-full-control"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-write-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }
}

# --- Stronger forms applied too narrowly ---

# A deny with no condition on s3:PutObjectAcl only: 1 finding
resource "aws_vpc_endpoint" "denyall_noversion" {
  vpc_id            = "vpc-0147"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*" }
  ]
}
POLICY
}

# Null true denies only requests without the grant header: 1 finding
resource "aws_vpc_endpoint" "nulltrue" {
  vpc_id            = "vpc-0148"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"Null": {"s3:x-amz-grant-read": "true"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"Null": {"s3:x-amz-grant-read-acp": "true"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"Null": {"s3:x-amz-grant-write-acp": "true"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"Null": {"s3:x-amz-grant-full-control": "true"}} }
  ]
}
POLICY
}

# Canned ACL pattern "public-*" leaves authenticated-read open: 1 finding
resource "aws_vpc_endpoint" "publicstar" {
  vpc_id            = "vpc-0149"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-acl": "public-*"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*AllUsers*", "*AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*AllUsers*", "*AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*AllUsers*", "*AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*AllUsers*", "*AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# --- Operator names ---
# Operator names are case sensitive, so an operator written in another letter
# case does not count.

# Canned ACL deny under stringequals: 1 finding
resource "aws_vpc_endpoint" "oplowerjson" {
  vpc_id            = "vpc-0150"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"stringequals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}} }
  ]
}
POLICY
}

# Grant header denies under null false: 1 finding
resource "aws_vpc_endpoint" "nulllower" {
  vpc_id            = "vpc-0151"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"null": {"s3:x-amz-grant-read": "false"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"null": {"s3:x-amz-grant-read-acp": "false"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"null": {"s3:x-amz-grant-write-acp": "false"}} },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": {"null": {"s3:x-amz-grant-full-control": "false"}} }
  ]
}
POLICY
}

# Data-source canned ACL deny under stringequals: 1 finding
resource "aws_vpc_endpoint" "oplowerhcl" {
  vpc_id            = "vpc-0152"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.ds_oplowerhcl.json
}

data "aws_iam_policy_document" "ds_oplowerhcl" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "stringequals"
      variable = "s3:x-amz-acl"
      values   = ["public-read", "public-read-write", "authenticated-read"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-write-acp"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-full-control"
      values   = ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]
    }
  }
}

# --- Never-created resources and statements the source does not show ---

# A endpoint policy that is never created (count = 0) does not protect its endpoint,
# even when it holds the required Deny.
resource "aws_vpc_endpoint" "zzncpol" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

data "aws_iam_policy_document" "zz_nc_doc" {
  statement {
    sid       = "DenyObjectAcls"
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint_policy" "zzncpol" {
  count           = 0
  vpc_endpoint_id = aws_vpc_endpoint.zzncpol.id
  policy          = data.aws_iam_policy_document.zz_nc_doc.json
}

# override_policy_documents replaces any written statement with the same
# sid, so a document that sets it cannot prove the Deny.
resource "aws_vpc_endpoint" "zzoverride" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

data "aws_iam_policy_document" "zz_override_src" {
  statement {
    sid       = "DenyObjectAcls"
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
    sid       = "DenyObjectAcls"
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint_policy" "zzoverride" {
  vpc_endpoint_id = aws_vpc_endpoint.zzoverride.id
  policy          = data.aws_iam_policy_document.zz_overridden.json
}

# A dynamic condition block adds conditions the source does not show, which
# can narrow the Deny, so that statement does not count.
resource "aws_vpc_endpoint" "zzdyncond" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

data "aws_iam_policy_document" "zz_dyn_cond" {
  statement {
    sid       = "DenyObjectAcls"
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
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

resource "aws_vpc_endpoint_policy" "zzdyncond" {
  vpc_endpoint_id = aws_vpc_endpoint.zzdyncond.id
  policy          = data.aws_iam_policy_document.zz_dyn_cond.json
}

# Effect is case sensitive, so "deny" is no Deny.
resource "aws_vpc_endpoint" "zzeffcase" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*"}]}
POLICY
}

# --- Competing endpoint policy sources ---

# An endpoint holds one policy, and its policy argument and an
# aws_vpc_endpoint_policy overwrite each other, so each must hold the
# control on its own: here the policy argument allows everything.
resource "aws_vpc_endpoint" "zzcompete" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*"}]}
POLICY
}

data "aws_iam_policy_document" "zz_compete_doc" {
  statement {
    sid       = "DenyObjectAcls"
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint_policy" "zzcompete" {
  vpc_endpoint_id = aws_vpc_endpoint.zzcompete.id
  policy          = data.aws_iam_policy_document.zz_compete_doc.json
}

# A requirement split between the policy argument and an
# aws_vpc_endpoint_policy is not met, since only one of them applies.
resource "aws_vpc_endpoint" "zzsplit" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.zz_split_inline.json
}

data "aws_iam_policy_document" "zz_split_inline" {
  statement {
    sid       = "DenyObjectAcl"
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "zz_split_standalone" {
  statement {
    sid       = "DenyObjectVersionAcl"
    effect    = "Deny"
    actions   = ["s3:PutObjectVersionAcl"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint_policy" "zzsplit" {
  vpc_endpoint_id = aws_vpc_endpoint.zzsplit.id
  policy          = data.aws_iam_policy_document.zz_split_standalone.json
}
