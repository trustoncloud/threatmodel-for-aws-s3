# S3.C2 (scp_secure_transport) - universal - VIOLATING
# One finding per missing protection: the Deny of unencrypted requests and the
# Deny of TLS versions below 1.2.

# SCP that does not enforce S3 secure transport (unrelated deny): 2 findings
resource "aws_organizations_policy" "no_transport" {
  name = "deny-leave-org"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveOrg",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    }
  ]
}
POLICY
}

# SCP that denies S3 but on the wrong condition (not transport): 2 findings
resource "aws_organizations_policy" "wrong_condition" {
  name = "deny-s3-wrong-cond"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3WrongCondition",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "StringNotEquals": { "aws:PrincipalOrgID": "o-example" } }
    }
  ]
}
POLICY
}

# Only the TLS floor: a plain HTTP request carries no s3:TlsVersion, so it is
# not denied: 1 finding (unencrypted requests)
resource "aws_organizations_policy" "tls_only" {
  name = "deny-old-tls-only"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOldTls",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Only the unencrypted-request Deny: old TLS versions stay open: 1 finding (TLS)
resource "aws_organizations_policy" "transport_only" {
  name = "deny-http-only"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureS3",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

# Both Denies, limited to names that start with "s": 2 findings
resource "aws_organizations_policy" "narrow_resource" {
  name = "deny-insecure-some-buckets"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::s*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::s*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Both Denies on buckets and objects only: a request through an access point
# names the access point ARN, so it is left out: 2 findings
resource "aws_organizations_policy" "buckets_only" {
  name = "deny-insecure-buckets-only"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# Both Denies carry a second condition, which narrows them: 2 findings
resource "aws_organizations_policy" "extra_condition" {
  name = "deny-insecure-outside-org"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "Bool": { "aws:SecureTransport": "false" },
        "StringNotEquals": { "aws:PrincipalOrgID": "o-example" }
      }
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": { "s3:TlsVersion": "1.2" },
        "StringNotEquals": { "aws:PrincipalOrgID": "o-example" }
      }
    }
  ]
}
POLICY
}

# Both Denies use NotResource, which leaves the named bucket open: 2 findings
resource "aws_organizations_policy" "not_resource" {
  name = "deny-insecure-except-one"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "NotResource": "arn:aws:s3:::legacy-bucket/*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "NotResource": "arn:aws:s3:::legacy-bucket/*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# TLS floor below 1.2 leaves TLS 1.1 open: 1 finding (TLS)
resource "aws_organizations_policy" "low_tls_floor" {
  name = "deny-below-tls-1-1"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.1" } }
    }
  ]
}
POLICY
}

# Content from a data source whose name starts with the name of a compliant
# one (ds_full) but holds no transport Deny: 2 findings
resource "aws_organizations_policy" "ds_lookalike" {
  name    = "deny-nothing-useful"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_full_weak.json
}

data "aws_iam_policy_document" "ds_full" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

data "aws_iam_policy_document" "ds_full_weak" {
  statement {
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

# Data source Denies that exempt some actions with not_actions: 2 findings
resource "aws_organizations_policy" "ds_not_actions" {
  name    = "deny-insecure-most-actions"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_except_actions.json
}

data "aws_iam_policy_document" "ds_except_actions" {
  statement {
    effect      = "Deny"
    not_actions = ["s3:GetObject"]
    resources   = ["*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    effect      = "Deny"
    not_actions = ["s3:GetObject"]
    resources   = ["*"]

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

# Content the source does not show (a variable): 1 finding
variable "scp_content" {
  type = string
}

resource "aws_organizations_policy" "unreadable" {
  name    = "from-variable"
  type    = "SERVICE_CONTROL_POLICY"
  content = var.scp_content
}
