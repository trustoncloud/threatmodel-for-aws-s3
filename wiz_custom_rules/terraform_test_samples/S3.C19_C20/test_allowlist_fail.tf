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

# --- Operator names ---

# Authorized org under stringnotequals: operator names are case sensitive, so
# it does not count as StringNotEquals: 1 finding
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
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
POLICY
}

# Data-source deny for the authorized org under stringnotequalsifexists: 1 finding
resource "aws_vpc_endpoint" "oplowerhcl" {
  vpc_id            = "vpc-0231"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.ds_oplowerhcl.json
}

data "aws_iam_policy_document" "ds_oplowerhcl" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "stringnotequalsifexists"
      variable = "aws:PrincipalOrgID"
      values   = ["o-exampleorgid"]
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
