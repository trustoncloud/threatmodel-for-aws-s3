# S3.C2 (scp_secure_transport) - universal - COMPLIANT (0 findings)

# SCP with an inline (heredoc) Deny on insecure S3 transport
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
    }
  ]
}
POLICY
}

# SCP whose content comes from a policy-document data source (TLS floor form)
resource "aws_organizations_policy" "s3_tls_ds" {
  name    = "deny-old-tls-s3"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.s3_tls_ds.json
}

data "aws_iam_policy_document" "s3_tls_ds" {
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

# A non-SCP policy (tag policy): out of scope, must not produce a finding
resource "aws_organizations_policy" "tags" {
  name    = "tag-policy"
  type    = "TAG_POLICY"
  content = "{\"tags\":{}}"
}
