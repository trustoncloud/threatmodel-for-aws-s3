# S3.C24 (vpc_endpoint_bucket_restriction) - allowlist - COMPLIANT (0 findings)

resource "aws_vpc_endpoint" "s3_scoped" {
  vpc_id            = "vpc-0aaa"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::authorized-bucket",
        "arn:aws:s3:::authorized-bucket/*"
      ]
    }
  ]
}
POLICY
}

# Non-S3 endpoint: out of scope
resource "aws_vpc_endpoint" "kms_ep" {
  vpc_id            = "vpc-0bbb"
  service_name      = "com.amazonaws.us-east-1.kms"
  vpc_endpoint_type = "Interface"
}

# Allow scoped to the authorized bucket, from a policy-document data source
resource "aws_vpc_endpoint" "ep_from_doc" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_bucket_doc.json
}

data "aws_iam_policy_document" "pol_bucket_doc" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::authorized-bucket",
      "arn:aws:s3:::authorized-bucket/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
