# S3.C36 (vpc_endpoint_block_public_acl) - universal - COMPLIANT (0 findings)

resource "aws_vpc_endpoint" "s3_blockacl" {
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
      "Action": "s3:PutObjectAcl",
      "Resource": "*",
      "Condition": { "StringEquals": { "s3:x-amz-acl": ["public-read", "public-read-write"] } }
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "ec2_ep" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.ec2"
  vpc_endpoint_type = "Interface"
}

# Policy from a policy-document data source, blocking public object ACLs
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0ddd"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_blockacl_doc.json
}

data "aws_iam_policy_document" "pol_blockacl_doc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:PutObjectAcl"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["public-read", "public-read-write"]
    }
  }
}
