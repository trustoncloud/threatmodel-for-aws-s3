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
