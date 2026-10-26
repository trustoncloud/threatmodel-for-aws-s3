# S3.C5 (vpc_endpoint_secure_transport) - universal - VIOLATING

# S3 endpoint whose policy does not deny insecure transport: 1 finding
resource "aws_vpc_endpoint" "s3_open" {
  vpc_id            = "vpc-0ddd"
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

# S3 endpoint with no policy (default full access): 1 finding
resource "aws_vpc_endpoint" "s3_nopolicy" {
  vpc_id            = "vpc-0eee"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
}

# Transport deny applies to one role only: 1 finding
resource "aws_vpc_endpoint" "onerole" {
  vpc_id            = "vpc-0f01"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy = <<POLICY
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POLICY
}

# Transport deny reaches one bucket only: 1 finding
resource "aws_s3_bucket" "epbucket" {
  bucket = "endpoint-target-bucket"
}

resource "aws_vpc_endpoint" "onebucket" {
  vpc_id            = "vpc-0f02"
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.ds_onebucket.json
}

data "aws_iam_policy_document" "ds_onebucket" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = [aws_s3_bucket.epbucket.arn, "${aws_s3_bucket.epbucket.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# Transport deny narrowed by an extra condition: 1 finding
resource "aws_vpc_endpoint" "extracond" {
  vpc_id            = "vpc-0f03"
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
      "Condition": {
        "Bool": { "aws:SecureTransport": "false" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}
