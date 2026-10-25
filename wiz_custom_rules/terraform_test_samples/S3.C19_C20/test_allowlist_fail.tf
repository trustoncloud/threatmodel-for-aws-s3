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
