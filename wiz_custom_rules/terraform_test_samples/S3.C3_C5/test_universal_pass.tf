# S3.C5 (vpc_endpoint_secure_transport) - universal - COMPLIANT (0 findings)

# Inline policy denying unencrypted requests and old TLS versions
resource "aws_vpc_endpoint" "s3_secure" {
  vpc_id            = "vpc-0aaa"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Compliant policy attached via the standalone aws_vpc_endpoint_policy resource
resource "aws_vpc_endpoint" "s3_assoc" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "s3_assoc" {
  vpc_endpoint_id = aws_vpc_endpoint.s3_assoc.id
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope, must not produce a finding
resource "aws_vpc_endpoint" "ssm_ep" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.ssm"
  vpc_endpoint_type = "Interface"
}

# Policy from a policy-document data source with both denies
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0fff"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_transport_doc.json
}

data "aws_iam_policy_document" "pol_transport_doc" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
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
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

# TLS floor above 1.2, AWS wildcard principal, all-bucket patterns, via a
# standalone policy
resource "aws_vpc_endpoint" "floor13" {
  vpc_id            = "vpc-0abc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "floor13" {
  vpc_endpoint_id = aws_vpc_endpoint.floor13.id
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "*" },
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"],
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.3" } }
    },
    {
      "Effect": "Deny",
      "Principal": { "AWS": "*" },
      "Action": "s3:*",
      "Resource": "arn:*:s3:::*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

# Resource scope passed in as a variable: not known in the source, so it is
# not judged
variable "deny_scope" {
  type = string
}

resource "aws_vpc_endpoint" "scopevar" {
  vpc_id            = "vpc-0abd"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_scopevar_doc.json
}

data "aws_iam_policy_document" "pol_scopevar_doc" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = [var.deny_scope]

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
    actions   = ["*"]
    resources = [var.deny_scope]

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

# Both denies exempt AWS service principals with aws:PrincipalIsAWSService
# false under BoolIfExists (anonymous requests omit the key and stay denied);
# the TLS deny in its IfExists spelling, its exemption in its own block
resource "aws_vpc_endpoint" "exempt_services" {
  vpc_id            = "vpc-0ab1"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*" },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "BoolIfExists": { "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false" } }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThanIfExists": { "s3:TlsVersion": "1.2" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
POLICY
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

data "aws_iam_policy_document" "zz_both_standalone" {
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

resource "aws_vpc_endpoint_policy" "zzbothgood" {
  vpc_endpoint_id = aws_vpc_endpoint.zzbothgood.id
  policy          = data.aws_iam_policy_document.zz_both_standalone.json
}
