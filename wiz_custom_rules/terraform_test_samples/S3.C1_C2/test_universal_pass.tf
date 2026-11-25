# S3.C2 (scp_secure_transport) - universal - COMPLIANT (0 findings)
# The SCPs attached to each organization root hold both Denies between them,
# each on every S3 resource: unencrypted requests (aws:SecureTransport false)
# and TLS versions below 1.2. A literal root ID, the organization resource and
# the organization data source count as three roots, and each passes on its
# own. SCPs attached elsewhere are not judged.

resource "aws_organizations_organization" "org" {
  feature_set          = "ALL"
  enabled_policy_types = ["SERVICE_CONTROL_POLICY", "TAG_POLICY"]
}

data "aws_organizations_organization" "current" {}

# Transport Deny exempting AWS service principals under BoolIfExists
# (anonymous requests omit the key and stay denied), attached through the
# organization resource
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
      "Condition": { "BoolIfExists": { "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false" } }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "root_transport" {
  policy_id = aws_organizations_policy.s3_transport.id
  target_id = aws_organizations_organization.org.roots[0].id
}

# TLS Deny in its IfExists spelling, exempting AWS service principals, in a
# second SCP on the same root
resource "aws_organizations_policy" "s3_tls" {
  name    = "deny-old-tls-s3"
  type    = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThanIfExists": { "s3:TlsVersion": "1.2" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "root_tls" {
  policy_id = aws_organizations_policy.s3_tls.id
  target_id = aws_organizations_organization.org.roots[0].id
}

# Every S3 resource written as an S3 ARN pattern, a TLS floor of 1.3 and the
# IfExists transport test, attached by the literal root ID and through the
# organization data source. No type means a service control policy.
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

resource "aws_organizations_policy_attachment" "root_literal" {
  policy_id = aws_organizations_policy.s3_arn_scope.id
  target_id = "r-exam"
}

resource "aws_organizations_policy_attachment" "root_data_source" {
  policy_id = aws_organizations_policy.s3_arn_scope.id
  target_id = data.aws_organizations_organization.current.roots[0].id
}

# The default full-access SCP on the root holds no Deny and changes nothing
resource "aws_organizations_policy_attachment" "root_full_access" {
  policy_id = "p-FullAWSAccess"
  target_id = aws_organizations_organization.org.roots[0].id
}

# An SCP without either Deny, attached to an OU and to an account: not judged
resource "aws_organizations_organizational_unit" "workloads" {
  name      = "workloads"
  parent_id = aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_policy" "leave_org" {
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

resource "aws_organizations_policy_attachment" "ou_leave_org" {
  policy_id = aws_organizations_policy.leave_org.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_policy_attachment" "account_leave_org" {
  policy_id = aws_organizations_policy.leave_org.id
  target_id = "111122223333"
}

# An SCP attached to no target: not judged
resource "aws_organizations_policy" "unattached" {
  name = "deny-nothing-useful"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*" }
  ]
}
POLICY
}

# A tag policy on the root: out of scope, must not produce a finding
resource "aws_organizations_policy" "tags" {
  name    = "tag-policy"
  type    = "TAG_POLICY"
  content = "{\"tags\":{}}"
}

resource "aws_organizations_policy_attachment" "root_tags" {
  policy_id = aws_organizations_policy.tags.id
  target_id = aws_organizations_organization.org.roots[0].id
}

# Both Denies exempt AWS service principals under plain Bool, the form the S3
# condition-key example shows. An SCP governs only the organization's
# principals, whose signed requests always carry aws:PrincipalIsAWSService, so
# plain Bool exempts the same requests as BoolIfExists
resource "aws_organizations_policy" "s3_bool_exempt" {
  name = "deny-insecure-s3-plain-bool-exemption"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false" } }
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": { "s3:TlsVersion": "1.2" },
        "Bool": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "root_bool_exempt" {
  policy_id = aws_organizations_policy.s3_bool_exempt.id
  target_id = "r-bool"
}

# Root r-mini: the transport Deny above and a TLS Deny from a data source
# referenced through minified_json
resource "aws_organizations_policy" "s3_tls_minified" {
  name    = "deny-old-tls-s3-minified"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_minified_tls.minified_json
}

data "aws_iam_policy_document" "ds_minified_tls" {
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

resource "aws_organizations_policy_attachment" "root_mini_transport" {
  policy_id = aws_organizations_policy.s3_transport.id
  target_id = "r-mini"
}

resource "aws_organizations_policy_attachment" "root_mini_tls" {
  policy_id = aws_organizations_policy.s3_tls_minified.id
  target_id = "r-mini"
}

# --- Never-created resources and statements the source does not show ---

# An organization that is never created is not judged.
resource "aws_organizations_organization" "zz_unused_org" {
  count       = 0
  feature_set = "ALL"
}

# An attachment that is never created attaches nothing, so its root is not
# judged.
resource "aws_organizations_policy" "zz_weak_scp" {
  name    = "zz-weak-scp"
  type    = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}]}
POLICY
}

resource "aws_organizations_policy_attachment" "zz_never_attached" {
  count     = 0
  policy_id = aws_organizations_policy.zz_weak_scp.id
  target_id = "r-weak"
}

# source_policy_documents adds statements; the written Denies still count.
data "aws_iam_policy_document" "zz_scp_source" {
  statement {
    sid       = "StayInOrg"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "zz_scp_sourced" {
  source_policy_documents = [data.aws_iam_policy_document.zz_scp_source.json]

  statement {
    sid       = "DenyInsecureTransport"
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
    sid       = "DenyOldTls"
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

resource "aws_organizations_policy" "zz_src_scp" {
  name    = "zz-src-scp"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.zz_scp_sourced.json
}

resource "aws_organizations_policy_attachment" "zz_root_src" {
  policy_id = aws_organizations_policy.zz_src_scp.id
  target_id = "r-srcd"
}
