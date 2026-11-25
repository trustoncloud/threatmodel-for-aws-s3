# S3.C36 (vpc_endpoint_block_public_acl) - universal - COMPLIANT (0 findings)

# Every public canned ACL and each grant header denied for both actions
resource "aws_vpc_endpoint" "s3_blockacl" {
  vpc_id            = "vpc-0aaa"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*" },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"],
      "Resource": "*",
      "Condition": { "StringEquals": { "s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"] } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"],
      "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"],
      "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"],
      "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"],
      "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } }
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "ec2_ep" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.ec2"
  vpc_endpoint_type = "Interface"
}

# Policy from a policy-document data source, one statement per header
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0ddd"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_blockacl_doc.json
}

data "aws_iam_policy_document" "pol_blockacl_doc" {
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

# --- Scope, operator and lookalike cases ---

# Actions, canned ACLs and groups split across statements
resource "aws_vpc_endpoint" "splitvals" {
  vpc_id            = "vpc-0130"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": { "StringEquals": { "s3:x-amz-acl": "public-read" } } },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectAcl", "Resource": "*",
      "Condition": { "StringEquals": { "s3:x-amz-acl": ["public-read-write", "authenticated-read"] } } },
    { "Effect": "Deny", "Principal": "*", "Action": "s3:PutObjectVersionAcl", "Resource": "*",
      "Condition": { "StringEquals": { "s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"] } } },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-read": "*http://acs.amazonaws.com/groups/global/AllUsers*" } } },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-read": "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*" } } },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-read-acp": ["*AllUsers*", "*AuthenticatedUsers*"] } } },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-write-acp": "*acs.amazonaws.com/groups/global/*" } } },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "*",
      "Condition": { "StringLike": { "s3:x-amz-grant-full-control": "*" } } }
  ]
}
POLICY
}

# IfExists forms, an action pattern that matches both actions, every object, AWS wildcard principal
resource "aws_vpc_endpoint" "ifexists" {
  vpc_id            = "vpc-0131"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": ["s3:PutObject*"], "Resource": "arn:aws:s3:::*/*",
      "Condition": { "StringEqualsIfExists": { "s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"] } } },
    { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": ["s3:PutObject*"], "Resource": "arn:aws:s3:::*/*",
      "Condition": { "StringLikeIfExists": { "s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } } },
    { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": ["s3:PutObject*"], "Resource": "arn:aws:s3:::*/*",
      "Condition": { "StringLikeIfExists": { "s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } } },
    { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": ["s3:PutObject*"], "Resource": "arn:aws:s3:::*/*",
      "Condition": { "StringLikeIfExists": { "s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } } },
    { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": ["s3:PutObject*"], "Resource": "arn:aws:s3:::*/*",
      "Condition": { "StringLikeIfExists": { "s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"] } } }
  ]
}
POLICY
}

# Data-source denies on every object, attached via the standalone endpoint-policy resource
resource "aws_vpc_endpoint" "docassoc" {
  vpc_id            = "vpc-0132"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "docassoc" {
  vpc_endpoint_id = aws_vpc_endpoint.docassoc.id
  policy          = data.aws_iam_policy_document.pd_aclassoc.json
}

data "aws_iam_policy_document" "pd_aclassoc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "AWS"
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
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read"
      values   = ["*AllUsers*", "*AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-read-acp"
      values   = ["*AllUsers*", "*AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-write-acp"
      values   = ["*AllUsers*", "*AuthenticatedUsers*"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-grant-full-control"
      values   = ["*AllUsers*", "*AuthenticatedUsers*"]
    }
  }
}

# --- Stronger forms ---

# A deny with no condition blocks every ACL write
resource "aws_vpc_endpoint" "denyall" {
  vpc_id            = "vpc-0133"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*" },
    { "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*" }
  ]
}
POLICY
}

# Canned ACLs matched by patterns, grant headers denied whenever present (Null false)
resource "aws_vpc_endpoint" "nullgrants" {
  vpc_id            = "vpc-0134"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_nullgrants.json
}

data "aws_iam_policy_document" "pd_nullgrants" {
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
      variable = "s3:x-amz-acl"
      values   = ["public-*", "authenticated-read"]
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
      test     = "Null"
      variable = "s3:x-amz-grant-read"
      values   = ["false"]
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
      test     = "Null"
      variable = "s3:x-amz-grant-read-acp"
      values   = ["false"]
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
      test     = "Null"
      variable = "s3:x-amz-grant-write-acp"
      values   = ["false"]
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
      test     = "Null"
      variable = "s3:x-amz-grant-full-control"
      values   = ["false"]
    }
  }
}

# --- Never-created resources and statements the source does not show ---

# A S3 VPC endpoint that is never created (count = 0, or for_each over an empty
# collection) is not judged, even with no endpoint policy.
resource "aws_vpc_endpoint" "zzncsubj" {
  count             = 0
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint" "zzfesubj" {
  for_each          = toset([])
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

# source_policy_documents adds statements; the document's own statements win
# on a shared sid, so the written Deny still counts.
resource "aws_vpc_endpoint" "zzsrcadd" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

data "aws_iam_policy_document" "zz_src_extra" {
  statement {
    sid       = "ReadObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "zz_src_added" {
  source_policy_documents = [data.aws_iam_policy_document.zz_src_extra.json]

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

resource "aws_vpc_endpoint_policy" "zzsrcadd" {
  vpc_endpoint_id = aws_vpc_endpoint.zzsrcadd.id
  policy          = data.aws_iam_policy_document.zz_src_added.json
}

# --- Competing endpoint policy sources ---

# An endpoint holds one policy, and its policy argument and an
# aws_vpc_endpoint_policy overwrite each other: when both hold the control,
# whichever applies holds it.
resource "aws_vpc_endpoint" "zzbothgood" {
  vpc_id            = "vpc-0123456789abcdef0"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.zz_both_inline.json
}

data "aws_iam_policy_document" "zz_both_inline" {
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

data "aws_iam_policy_document" "zz_both_standalone" {
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

resource "aws_vpc_endpoint_policy" "zzbothgood" {
  vpc_endpoint_id = aws_vpc_endpoint.zzbothgood.id
  policy          = data.aws_iam_policy_document.zz_both_standalone.json
}
