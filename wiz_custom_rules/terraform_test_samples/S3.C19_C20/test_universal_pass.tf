# S3.C20 (vpc_endpoint_org_restriction) - universal - COMPLIANT (0 findings)

resource "aws_vpc_endpoint" "s3_org" {
  vpc_id            = "vpc-0aaa"
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
      "Condition": { "StringNotEquals": { "aws:PrincipalOrgID": "o-anyorg" } }
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "dynamodb_ep" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
}

# Org restriction from a policy-document data source, attached via the
# standalone endpoint-policy resource
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0eee"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint_policy" "ep_from_doc" {
  vpc_endpoint_id = aws_vpc_endpoint.ep_from_doc.id
  policy          = data.aws_iam_policy_document.pol_org_doc.json
}

data "aws_iam_policy_document" "pol_org_doc" {
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
      values   = ["o-anyorg"]
    }
  }
}
