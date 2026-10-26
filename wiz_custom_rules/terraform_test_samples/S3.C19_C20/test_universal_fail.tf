# S3.C20 (vpc_endpoint_org_restriction) - universal - VIOLATING

# S3 endpoint with no organization restriction: 1 finding
resource "aws_vpc_endpoint" "s3_noorg" {
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
