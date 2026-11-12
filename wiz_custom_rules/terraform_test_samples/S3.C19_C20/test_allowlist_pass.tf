# S3.C20 (vpc_endpoint_org_restriction) - allowlist - COMPLIANT (0 findings)

resource "aws_vpc_endpoint" "s3_authorg" {
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
      "Condition": { "StringNotEquals": { "aws:PrincipalOrgID": "o-exampleorgid" } }
    }
  ]
}
POLICY
}

# Org restriction from a policy-document data source, authorized org
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_org_doc.json
}

data "aws_iam_policy_document" "pol_org_doc" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-exampleorgid"]
    }
  }
}

# --- Scope, operator and lookalike cases ---

# IfExists form, S3 actions, all-bucket pattern, AWS wildcard principal
resource "aws_vpc_endpoint" "ifexists" {
  vpc_id            = "vpc-010f"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": [
            "o-exampleorgid"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Data-source org deny attached via the standalone endpoint-policy resource
resource "aws_vpc_endpoint" "docassoc" {
  vpc_id            = "vpc-0110"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "docassoc" {
  vpc_endpoint_id = aws_vpc_endpoint.docassoc.id
  policy          = data.aws_iam_policy_document.pd_orgassoc.json
}

data "aws_iam_policy_document" "pd_orgassoc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "aws:PrincipalOrgID"
      values   = ["o-exampleorgid"]
    }
  }
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "dynamodb_ep" {
  vpc_id            = "vpc-0bbc"
  service_name      = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
}

# Org paths under ForAllValues:StringNotLike; each value is compared as text with the configured list
resource "aws_vpc_endpoint" "pathsforall" {
  vpc_id            = "vpc-0124"
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
      "Condition": {
        "ForAllValues:StringNotLike": {
          "aws:PrincipalOrgPaths": ["o-exampleorgid"]
        }
      }
    }
  ]
}
POLICY
}

# Org paths under ForAllValues:StringNotEquals from a data source
resource "aws_vpc_endpoint" "pathsforalldoc" {
  vpc_id            = "vpc-0125"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_paths_forall.json
}

data "aws_iam_policy_document" "pd_paths_forall" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalOrgPaths"
      values   = ["o-exampleorgid"]
    }
  }
}
