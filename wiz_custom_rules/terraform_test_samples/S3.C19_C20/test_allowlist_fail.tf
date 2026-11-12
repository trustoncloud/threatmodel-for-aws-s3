# S3.C20 (vpc_endpoint_org_restriction) - allowlist - VIOLATING

# S3 endpoint with no organization restriction: 1 finding
resource "aws_vpc_endpoint" "s3_norestrict" {
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

# S3 endpoint restricting to an unauthorized organization: 1 finding
resource "aws_vpc_endpoint" "s3_rogueorg" {
  vpc_id            = "vpc-0ddd"
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
      "Condition": { "StringNotEquals": { "aws:PrincipalOrgID": "o-rogueorg" } }
    }
  ]
}
POLICY
}

# Org restriction from a policy-document data source allowing an unauthorized
# org: 1 finding
resource "aws_vpc_endpoint" "ep_bad_doc" {
  vpc_id            = "vpc-0eee"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_bad_org_doc.json
}

data "aws_iam_policy_document" "pol_bad_org_doc" {
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
      values   = ["o-rogueorg2"]
    }
  }
}

# --- Scope, operator and lookalike cases ---

# Org deny applies to one role only: 1 finding
resource "aws_vpc_endpoint" "onerole" {
  vpc_id            = "vpc-0101"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny covers one action only: 1 finding
resource "aws_vpc_endpoint" "oneaction" {
  vpc_id            = "vpc-0102"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny reaches one bucket only: 1 finding
resource "aws_vpc_endpoint" "onebkt" {
  vpc_id            = "vpc-0103"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny on a pattern that only matches names starting with "s": 1 finding
resource "aws_vpc_endpoint" "prefixlook" {
  vpc_id            = "vpc-0104"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny narrowed by a second condition: 1 finding
resource "aws_vpc_endpoint" "extracond" {
  vpc_id            = "vpc-0105"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
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
  vpc_id            = "vpc-0106"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny under StringNotLike: 1 finding
resource "aws_vpc_endpoint" "notlikeop" {
  vpc_id            = "vpc-0107"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny written with NotPrincipal: 1 finding
resource "aws_vpc_endpoint" "notprinc" {
  vpc_id            = "vpc-0108"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org deny written with NotResource: 1 finding
resource "aws_vpc_endpoint" "notres" {
  vpc_id            = "vpc-0109"
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Data-source org deny that reaches one bucket only: 1 finding
resource "aws_vpc_endpoint" "docnarrow" {
  vpc_id            = "vpc-010a"
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
      values   = ["o-exampleorgid"]
    }
  }
}

# Data-source org deny written with not_resources: 1 finding
resource "aws_vpc_endpoint" "docexclude" {
  vpc_id            = "vpc-010b"
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
      values   = ["o-exampleorgid"]
    }
  }
}

# Data-source org deny under ForAnyValue:StringNotEquals: 1 finding
resource "aws_vpc_endpoint" "docforany" {
  vpc_id            = "vpc-010c"
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
      values   = ["o-exampleorgid"]
    }
  }
}

# An authorized org next to an unauthorized one: 1 finding
resource "aws_vpc_endpoint" "mixedvals" {
  vpc_id            = "vpc-010d"
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
          "aws:PrincipalOrgID": [
            "o-exampleorgid",
            "o-rogueorg3"
          ]
        }
      }
    }
  ]
}
POLICY
}

# An org ID that only starts with the authorized one: 1 finding
resource "aws_vpc_endpoint" "orglook" {
  vpc_id            = "vpc-010e"
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
          "aws:PrincipalOrgID": "o-exampleorgid2"
        }
      }
    }
  ]
}
POLICY
}

# --- Operators by condition key ---

# Org paths under ForAnyValue:StringNotLike (a principal with no paths passes the deny): 1 finding
resource "aws_vpc_endpoint" "pathsforany" {
  vpc_id            = "vpc-0120"
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
          "aws:PrincipalOrgPaths": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org paths under plain StringNotEquals, an operator for a single value: 1 finding
resource "aws_vpc_endpoint" "pathsplain" {
  vpc_id            = "vpc-0121"
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
          "aws:PrincipalOrgPaths": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Org ID under ForAllValues:StringNotEquals, a set operator on a key that holds one value: 1 finding
resource "aws_vpc_endpoint" "orgidforall" {
  vpc_id            = "vpc-0122"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_orgid_forall.json
}

data "aws_iam_policy_document" "pd_orgid_forall" {
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
      values   = ["o-exampleorgid"]
    }
  }
}

# Org paths with a pattern that is not in the list: 1 finding
resource "aws_vpc_endpoint" "pathsunlisted" {
  vpc_id            = "vpc-0123"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pd_paths_unlisted.json
}

data "aws_iam_policy_document" "pd_paths_unlisted" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ForAllValues:StringNotLike"
      variable = "aws:PrincipalOrgPaths"
      values   = ["o-exampleorgid", "o-exampleorgid/*"]
    }
  }
}
