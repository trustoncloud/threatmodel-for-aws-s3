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

# --- Operator names ---

# Org deny under stringnotequals: operator names are case sensitive, so it
# does not count as StringNotEquals: 1 finding
resource "aws_vpc_endpoint" "oplowerjson" {
  vpc_id            = "vpc-0230"
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
        "stringnotequals": {
          "aws:PrincipalOrgID": "o-anyorg"
        }
      }
    }
  ]
}
POLICY
}

# Org paths under forallvalues:stringnotlike: 1 finding
resource "aws_vpc_endpoint" "pathsoplower" {
  vpc_id            = "vpc-0231"
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
        "forallvalues:stringnotlike": {
          "aws:PrincipalOrgPaths": "o-anyorg/r-ab12/*"
        }
      }
    }
  ]
}
POLICY
}

# Data-source account deny under STRINGNOTEQUALSIFEXISTS: 1 finding
resource "aws_vpc_endpoint" "opupperhcl" {
  vpc_id            = "vpc-0232"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.ds_opupperhcl.json
}

data "aws_iam_policy_document" "ds_opupperhcl" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "STRINGNOTEQUALSIFEXISTS"
      variable = "aws:PrincipalAccount"
      values   = ["111122223333"]
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
    sid       = "OnlyOurOrganization"
    effect    = "Deny"
    actions   = ["s3:*"]
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
    sid       = "OnlyOurOrganization"
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
    sid       = "OnlyOurOrganization"
    effect    = "Deny"
    actions   = ["s3:*"]
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
    sid       = "OnlyOurOrganization"
    effect    = "Deny"
    actions   = ["s3:*"]
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
{"Version": "2012-10-17", "Statement": [{"Effect": "deny", "Principal": "*", "Action": "s3:*", "Resource": "*", "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}}]}
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
    sid       = "OnlyOurOrganization"
    effect    = "Deny"
    actions   = ["s3:*"]
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

resource "aws_vpc_endpoint_policy" "zzcompete" {
  vpc_endpoint_id = aws_vpc_endpoint.zzcompete.id
  policy          = data.aws_iam_policy_document.zz_compete_doc.json
}
