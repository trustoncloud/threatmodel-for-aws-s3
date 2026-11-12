# S3.C20 (vpc_endpoint_org_restriction) - universal - VIOLATING

# S3 endpoint with no organization restriction: 1 finding
resource "aws_vpc_endpoint" "s3_noorg" {
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

# Org deny applies to one role only: 1 finding
resource "aws_vpc_endpoint" "onerole" {
  vpc_id            = "vpc-0111"
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
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny covers one action only: 1 finding
resource "aws_vpc_endpoint" "oneaction" {
  vpc_id            = "vpc-0112"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny reaches one bucket only: 1 finding
resource "aws_vpc_endpoint" "onebkt" {
  vpc_id            = "vpc-0113"
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
      "Resource": [
        "arn:aws:s3:::one-bucket",
        "arn:aws:s3:::one-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny on a pattern that only matches names starting with "s": 1 finding
resource "aws_vpc_endpoint" "prefixlook" {
  vpc_id            = "vpc-0114"
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
      "Resource": "arn:aws:s3:::s*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny narrowed by a second condition: 1 finding
resource "aws_vpc_endpoint" "extracond" {
  vpc_id            = "vpc-0115"
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
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        },
        "Bool": {
          "aws:ViaAWSService": "false"
        }
      }
    }
  ]
}
POLICY
}

# Org deny under ForAnyValue:StringNotEquals: 1 finding
resource "aws_vpc_endpoint" "foranyop" {
  vpc_id            = "vpc-0116"
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
        "ForAnyValue:StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny under StringNotLike: 1 finding
resource "aws_vpc_endpoint" "notlikeop" {
  vpc_id            = "vpc-0117"
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
        "StringNotLike": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny written with NotPrincipal: 1 finding
resource "aws_vpc_endpoint" "notprinc" {
  vpc_id            = "vpc-0118"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "NotPrincipal": {
        "AWS": "arn:aws:iam::111122223333:role/legacy"
      },
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org deny written with NotResource: 1 finding
resource "aws_vpc_endpoint" "notres" {
  vpc_id            = "vpc-0119"
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
      "NotResource": "arn:aws:s3:::legacy-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Data-source org deny that reaches one bucket only: 1 finding
resource "aws_vpc_endpoint" "docnarrow" {
  vpc_id            = "vpc-011a"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_onebucket.json
}

data "aws_iam_policy_document" "pd_onebucket" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["arn:aws:s3:::one-bucket", "arn:aws:s3:::one-bucket/*"]

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

# Data-source org deny written with not_resources: 1 finding
resource "aws_vpc_endpoint" "docexclude" {
  vpc_id            = "vpc-011b"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_notresources.json
}

data "aws_iam_policy_document" "pd_notresources" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    not_resources = ["arn:aws:s3:::legacy-bucket/*"]

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

# Data-source org deny under ForAnyValue:StringNotEquals: 1 finding
resource "aws_vpc_endpoint" "docforany" {
  vpc_id            = "vpc-011c"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_setoperator.json
}

data "aws_iam_policy_document" "pd_setoperator" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ForAnyValue:StringNotEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-anyorg"]
    }
  }
}

# --- Operators by condition key ---

# Org paths under ForAnyValue:StringNotLike (a principal with no paths passes the deny): 1 finding
resource "aws_vpc_endpoint" "pathsforany" {
  vpc_id            = "vpc-0220"
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
        "ForAnyValue:StringNotLike": {
          "aws:PrincipalOrgPaths": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org paths under plain StringNotEquals, an operator for a single value: 1 finding
resource "aws_vpc_endpoint" "pathsplain" {
  vpc_id            = "vpc-0221"
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
        "StringNotEquals": {
          "aws:PrincipalOrgPaths": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org ID under ForAllValues:StringNotEquals, a set operator on a key that holds one value: 1 finding
resource "aws_vpc_endpoint" "orgidforall" {
  vpc_id            = "vpc-0222"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pdu_orgid_forall.json
}

data "aws_iam_policy_document" "pdu_orgid_forall" {
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
      variable = "aws:PrincipalOrgID"
      values   = ["o-anyorg"]
    }
  }
}
