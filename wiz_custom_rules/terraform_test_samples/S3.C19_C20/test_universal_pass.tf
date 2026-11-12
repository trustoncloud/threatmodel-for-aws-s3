# S3.C20 (vpc_endpoint_org_restriction) - universal - COMPLIANT (0 findings)

resource "aws_vpc_endpoint" "s3_org" {
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
      "Condition": { "StringNotEquals": { "aws:PrincipalOrgID": "o-anyorg" } }
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "dynamodb_ep" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
}

# Org restriction from a policy-document data source, attached via the
# standalone endpoint-policy resource
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0eee"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "ep_from_doc" {
  vpc_endpoint_id = aws_vpc_endpoint.ep_from_doc.id
  policy          = data.aws_iam_policy_document.pol_org_doc.json
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
      values   = ["o-anyorg"]
    }
  }
}

# --- Scope, operator and lookalike cases ---

# IfExists form on the account key, S3 actions, all-bucket pattern
resource "aws_vpc_endpoint" "ifexists" {
  vpc_id            = "vpc-011d"
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
          "aws:PrincipalAccount": [
            "111122223333"
          ]
        }
      }
    }
  ]
}
POLICY
}

# Org paths under ForAllValues:StringNotLike; each value is compared as text with the configured list
resource "aws_vpc_endpoint" "pathsforall" {
  vpc_id            = "vpc-0224"
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
          "aws:PrincipalOrgPaths": ["o-anyorg"]
        }
      }
    }
  ]
}
POLICY
}

# Org paths under ForAllValues:StringNotEquals from a data source
resource "aws_vpc_endpoint" "pathsforalldoc" {
  vpc_id            = "vpc-0225"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pdu_paths_forall.json
}

data "aws_iam_policy_document" "pdu_paths_forall" {
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
      values   = ["o-anyorg"]
    }
  }
}
