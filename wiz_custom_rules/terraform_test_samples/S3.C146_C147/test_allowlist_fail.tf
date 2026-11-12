# S3.C147 (bucket_enforce_ssec) - allowlist - VIOLATING

# Required bucket with a policy that does not enforce SSE-C: 1 finding
resource "aws_s3_bucket" "ssec_required" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssec_required" {
  bucket = aws_s3_bucket.ssec_required.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*"
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/ but the deny covers another path: 1 finding
resource "aws_s3_bucket" "mixedfail" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixedfail" {
  bucket = aws_s3_bucket.mixedfail.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/tmp/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Whole-bucket entry enforced for one role only: 1 finding
resource "aws_s3_bucket" "ssecrole" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecrole" {
  bucket = aws_s3_bucket.ssecrole.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" } }
    }
  ]
}
POLICY
}

# Whole-bucket entry narrowed by an extra condition: 1 finding
resource "aws_s3_bucket" "ssecextra" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecextra" {
  bucket = aws_s3_bucket.ssecextra.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" },
        "StringEquals": { "aws:PrincipalAccount": "111122223333" }
      }
    }
  ]
}
POLICY
}

# Whole-bucket entry, object pattern leaves keys out (literal ARN): 1 finding
resource "aws_s3_bucket" "ssecnarrow" {
  bucket = "ssec-required-bucket"
}

resource "aws_s3_bucket_policy" "ssecnarrow" {
  bucket = aws_s3_bucket.ssecnarrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ssec-required-bucket/s*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Path entry mixed-bucket/secure/, pattern leaves keys of the path out (reference): 1 finding
resource "aws_s3_bucket" "mixednarrow" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixednarrow" {
  bucket = aws_s3_bucket.mixednarrow.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": ["${aws_s3_bucket.mixednarrow.arn}/secure/s*", "${aws_s3_bucket.mixednarrow.arn}/secure/sample-object"],
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}

# Deny written with NotResource is never counted: 1 finding
resource "aws_s3_bucket" "ssecnot" {
  bucket = "ssec-required-bucket"
}

data "aws_iam_policy_document" "ssecnot" {
  statement {
    effect  = "Deny"
    actions = ["s3:PutObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    not_resources = ["arn:aws:s3:::ssec-required-bucket/public/*"]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["true"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssecnot" {
  bucket = aws_s3_bucket.ssecnot.id
  policy = data.aws_iam_policy_document.ssecnot.json
}

# Path entry mixed-bucket/secure/ with "secure/?*", which misses the key "secure/" itself: 1 finding
resource "aws_s3_bucket" "mixednonempty" {
  bucket = "mixed-bucket"
}

resource "aws_s3_bucket_policy" "mixednonempty" {
  bucket = aws_s3_bucket.mixednonempty.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mixed-bucket/secure/?*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "true" }
      }
    }
  ]
}
POLICY
}
