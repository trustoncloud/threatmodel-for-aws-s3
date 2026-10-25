# S3.C151 (bucket_policy_principal_check) - allowlist - VIOLATING

# Grants access to an unauthorized principal: 1 finding
resource "aws_s3_bucket" "rogue_principal" {
  bucket = "rogue-principal-bucket"
}

resource "aws_s3_bucket_policy" "rogue_principal" {
  bucket = aws_s3_bucket.rogue_principal.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRogue",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::999999999999:role/rogue-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::rogue-principal-bucket/*"
    }
  ]
}
POLICY
}

# Data-source policy with an omitted effect (defaults to Allow) granting an
# unauthorized principal: 1 finding
resource "aws_s3_bucket" "rogue_ds" {
  bucket = "rogue-ds-bucket"
}

data "aws_iam_policy_document" "rogue_ds" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::rogue-ds-bucket/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::999999999999:role/rogue-ds-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "rogue_ds" {
  bucket = aws_s3_bucket.rogue_ds.id
  policy = data.aws_iam_policy_document.rogue_ds.json
}
