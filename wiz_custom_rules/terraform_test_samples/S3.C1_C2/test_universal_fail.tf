# S3.C2 (scp_secure_transport) - universal - VIOLATING
# The SCPs attached to the root of the organization resource hold the
# transport Deny but no Deny of TLS versions below 1.2 that counts: 1 finding
# on the organization. Three attachments the source does not fully show:
# 1 finding each. Roots r-aaaa and r-bbbb each hold one Deny, which never
# combine across roots: 1 finding each. Root r-cccc holds only the transport
# Deny, read from a minified_json data source: 1 finding.

resource "aws_organizations_organization" "management_org" {
  feature_set          = "ALL"
  enabled_policy_types = ["SERVICE_CONTROL_POLICY", "TAG_POLICY"]
}

data "aws_organizations_organization" "caller_org" {}

# Transport Deny on the root: counts
resource "aws_organizations_policy" "transport" {
  name = "deny-insecure-s3"
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
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "org_root_transport" {
  policy_id = aws_organizations_policy.transport.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# TLS Deny narrowed by a second key beside the service exemption: does not count
resource "aws_organizations_policy" "tls_extra_key" {
  name = "deny-old-tls-outside-org"
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
        "NumericLessThan": { "s3:TlsVersion": "1.2" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" },
        "StringNotEquals": { "aws:PrincipalOrgID": "o-example" }
      }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "root_tls_extra_key" {
  policy_id = aws_organizations_policy.tls_extra_key.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# TLS Deny whose service exemption is true, which leaves every other
# principal out: does not count
resource "aws_organizations_policy" "tls_exempt_true" {
  name = "deny-old-tls-services-only"
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
        "NumericLessThan": { "s3:TlsVersion": "1.2" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "true" }
      }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "root_tls_exempt_true" {
  policy_id = aws_organizations_policy.tls_exempt_true.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# TLS Deny from a data source under an unrelated operator: does not count
resource "aws_organizations_policy" "tls_wrong_operator" {
  name    = "deny-old-tls-wrong-operator"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_wrong_operator.json
}

data "aws_iam_policy_document" "ds_wrong_operator" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]

    condition {
      test     = "NumericLessThanEquals"
      variable = "s3:TlsVersion"
      values   = ["1.1"]
    }
  }
}

resource "aws_organizations_policy_attachment" "root_tls_wrong_operator" {
  policy_id = aws_organizations_policy.tls_wrong_operator.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# TLS Deny on buckets and objects only: a request through an access point
# names the access point ARN, so it is left out: does not count
resource "aws_organizations_policy" "tls_buckets_only" {
  name = "deny-old-tls-buckets-only"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
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

resource "aws_organizations_policy_attachment" "root_tls_buckets_only" {
  policy_id = aws_organizations_policy.tls_buckets_only.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# A full TLS Deny attached to an OU only: OU enforcement is not judged, so it
# does not complete the root
resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "sandbox"
  parent_id = aws_organizations_organization.management_org.roots[0].id
}

resource "aws_organizations_policy" "tls_full" {
  name = "deny-old-tls-s3"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "ou_tls" {
  policy_id = aws_organizations_policy.tls_full.id
  target_id = aws_organizations_organizational_unit.sandbox.id
}

# Root attachment of an SCP whose content comes from a variable: 1 finding
variable "scp_content" {
  type = string
}

resource "aws_organizations_policy" "from_variable" {
  name    = "from-variable"
  type    = "SERVICE_CONTROL_POLICY"
  content = var.scp_content
}

resource "aws_organizations_policy_attachment" "root_unreadable" {
  policy_id = aws_organizations_policy.from_variable.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# Root attachment of a policy the source does not define: 1 finding
resource "aws_organizations_policy_attachment" "root_external_policy" {
  policy_id = "p-examplepolicy1"
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# Attachment to a target the source does not show: 1 finding
variable "scp_target_id" {
  type = string
}

resource "aws_organizations_policy_attachment" "unknown_target_tls" {
  policy_id = aws_organizations_policy.tls_full.id
  target_id = var.scp_target_id
}

# A tag policy on the root: out of scope
resource "aws_organizations_policy" "tag_rules" {
  name    = "tag-policy"
  type    = "TAG_POLICY"
  content = "{\"tags\":{}}"
}

resource "aws_organizations_policy_attachment" "root_tag_rules" {
  policy_id = aws_organizations_policy.tag_rules.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# More TLS Denies on the root that do not count, one shape each

# A TLS floor below 1.2 leaves TLS 1.1 open
resource "aws_organizations_policy" "tls_low_floor" {
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
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.1" } }
    }
  ]
}
POLICY
}

resource "aws_organizations_policy_attachment" "root_tls_low_floor" {
  policy_id = aws_organizations_policy.tls_low_floor.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# NotResource leaves the named bucket open; a pattern for names that start
# with "s" leaves other buckets open
resource "aws_organizations_policy" "tls_narrow" {
  name = "deny-old-tls-some-buckets"
  type = "SERVICE_CONTROL_POLICY"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "NotResource": "arn:aws:s3:::legacy-bucket/*",
      "Condition": { "NumericLessThan": { "s3:TlsVersion": "1.2" } }
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

resource "aws_organizations_policy_attachment" "root_tls_narrow" {
  policy_id = aws_organizations_policy.tls_narrow.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# Data source Deny that exempts some actions with not_actions
resource "aws_organizations_policy" "tls_not_actions" {
  name    = "deny-old-tls-most-actions"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_except_actions.json
}

data "aws_iam_policy_document" "ds_except_actions" {
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

resource "aws_organizations_policy_attachment" "root_tls_not_actions" {
  policy_id = aws_organizations_policy.tls_not_actions.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# Content from a data source whose name starts with the name of a compliant
# one (ds_full) but holds no TLS Deny
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

resource "aws_organizations_policy_attachment" "root_ds_lookalike" {
  policy_id = aws_organizations_policy.ds_lookalike.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# An SCP whose resource name starts with the name of the full TLS SCP
# (tls_full) is a different policy
resource "aws_organizations_policy" "tls_full_rogue" {
  name = "deny-nothing-at-all"
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

resource "aws_organizations_policy_attachment" "root_tls_full_rogue" {
  policy_id = aws_organizations_policy.tls_full_rogue.id
  target_id = aws_organizations_organization.management_org.roots[0].id
}

# The transport Deny on root r-aaaa and the TLS Deny on root r-bbbb: each root
# lacks one, and Denies on different roots never combine: 1 finding each
resource "aws_organizations_policy_attachment" "root_a_transport" {
  policy_id = aws_organizations_policy.transport.id
  target_id = "r-aaaa"
}

resource "aws_organizations_policy_attachment" "root_b_tls" {
  policy_id = aws_organizations_policy.tls_full.id
  target_id = "r-bbbb"
}

# Root r-cccc: an SCP from a data source referenced through minified_json holds
# the transport Deny and no TLS Deny: 1 finding
resource "aws_organizations_policy" "transport_minified" {
  name    = "deny-insecure-s3-minified"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.ds_minified_transport.minified_json
}

data "aws_iam_policy_document" "ds_minified_transport" {
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
}

resource "aws_organizations_policy_attachment" "root_c_minified" {
  policy_id = aws_organizations_policy.transport_minified.id
  target_id = "r-cccc"
}

# --- Never-created resources and statements the source does not show ---

# An attachment that is never created (count = 0) does not put its SCP on
# the root: r-ncat holds the transport Deny only.
data "aws_iam_policy_document" "zz_transport_only" {
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
}

resource "aws_organizations_policy" "zz_transport_scp" {
  name    = "zz-transport-scp"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.zz_transport_only.json
}

data "aws_iam_policy_document" "zz_tls_only" {
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

resource "aws_organizations_policy" "zz_tls_scp" {
  name    = "zz-tls-scp"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.zz_tls_only.json
}

resource "aws_organizations_policy_attachment" "zz_ncat_transport" {
  policy_id = aws_organizations_policy.zz_transport_scp.id
  target_id = "r-ncat"
}

resource "aws_organizations_policy_attachment" "zz_ncat_tls" {
  count     = 0
  policy_id = aws_organizations_policy.zz_tls_scp.id
  target_id = "r-ncat"
}

# override_policy_documents replaces any written statement with the same
# sid, so a document that sets it cannot prove the Denies.
data "aws_iam_policy_document" "zz_scp_override_src" {
  statement {
    sid       = "DenyOldTls"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "zz_scp_overridden" {
  override_policy_documents = [data.aws_iam_policy_document.zz_scp_override_src.json]

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

resource "aws_organizations_policy" "zz_override_scp" {
  name    = "zz-override-scp"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.zz_scp_overridden.json
}

resource "aws_organizations_policy_attachment" "zz_root_override" {
  policy_id = aws_organizations_policy.zz_override_scp.id
  target_id = "r-ovrd"
}

# A dynamic condition block adds conditions the source does not show, which
# can narrow the Deny, so that statement does not count.
data "aws_iam_policy_document" "zz_scp_dyn_cond" {
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

resource "aws_organizations_policy" "zz_dyn_cond_scp" {
  name    = "zz-dyn-cond-scp"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.zz_scp_dyn_cond.json
}

resource "aws_organizations_policy_attachment" "zz_root_dyn_cond" {
  policy_id = aws_organizations_policy.zz_dyn_cond_scp.id
  target_id = "r-dync"
}
