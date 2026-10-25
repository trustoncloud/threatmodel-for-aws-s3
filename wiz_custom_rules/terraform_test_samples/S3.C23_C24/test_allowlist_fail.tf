# S3.C24 (vpc_endpoint_bucket_restriction) - allowlist - VIOLATING

# S3 endpoint with no policy (default full access): 1 finding
resource "aws_vpc_endpoint" "s3_nopol" {
  vpc_id            = "vpc-0ccc"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

# S3 endpoint allowing an unauthorized bucket: 1 finding
resource "aws_vpc_endpoint" "s3_roguebkt" {
  vpc_id            = "vpc-0ddd"
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
      "Resource": "arn:aws:s3:::rogue-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy with an omitted effect (defaults to Allow) granting an
# unauthorized bucket: 1 finding
resource "aws_vpc_endpoint" "ep_bad_doc" {
  vpc_id            = "vpc-0eee"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.pol_bad_bucket_doc.json
}

data "aws_iam_policy_document" "pol_bad_bucket_doc" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::rogue-doc-bucket/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
