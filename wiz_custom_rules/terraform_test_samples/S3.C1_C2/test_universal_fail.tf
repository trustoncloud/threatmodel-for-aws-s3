# S3.C2 (scp_secure_transport) - universal - VIOLATING

# SCP that does not enforce S3 secure transport (unrelated deny): 1 finding
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

# SCP that denies S3 but on the wrong condition (not transport): 1 finding
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
