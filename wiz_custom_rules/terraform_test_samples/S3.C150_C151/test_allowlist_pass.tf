# S3.C151 (bucket_policy_principal_check) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "principal_ok" {
  bucket = "principal-ok-bucket"
}

resource "aws_s3_bucket_policy" "principal_ok" {
  bucket = aws_s3_bucket.principal_ok.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAuthorizedPrincipals",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::123456789012:role/authorized-role",
          "arn:aws:iam::123456789012:root"
        ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::principal-ok-bucket/*"
    }
  ]
}
POLICY
}
