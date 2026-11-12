# S3.C2 (scp_secure_transport) - universal - COMPLIANT (0 findings)
# Each SCP carries BOTH required Deny statements on every S3 resource:
# unencrypted requests (aws:SecureTransport false) and TLS versions below 1.2.

# SCP with inline (heredoc) Denies
resource "aws_organizations_policy" "s3_transport" {
  name = "deny-insecure-s3"
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
    },
    {
      "Sid": "DenyOldTlsS3",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

# SCP whose content comes from a policy-document data source
resource "aws_organizations_policy" "s3_tls_ds" {
  name    = "deny-insecure-s3-from-data-source"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_both.json
}

data "aws_iam_policy_document" "ds_both" {
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

# Every S3 resource written as an S3 ARN pattern, a TLS floor of 1.3, and the
# IfExists form of the transport test. No type means a service control policy.
resource "aws_organizations_policy" "s3_arn_scope" {
  name = "deny-insecure-s3-arn-scope"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["s3:*"],
      "Resource": ["arn:aws:s3:*"],
      "Condition": { "BoolIfExists": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": 1.3 } }
    }
  ]
}
POLICY
}

# A non-SCP policy (tag policy): out of scope, must not produce a finding
resource "aws_organizations_policy" "tags" {
  name    = "tag-policy"
  type    = "TAG_POLICY"
  content = "{\"tags\":{}}"
}
