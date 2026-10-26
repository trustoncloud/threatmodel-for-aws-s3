# S3.C36 (vpc_endpoint_block_public_acl) - universal - VIOLATING

# S3 endpoint that does not block public object ACLs: 1 finding
resource "aws_vpc_endpoint" "s3_nolock" {
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
