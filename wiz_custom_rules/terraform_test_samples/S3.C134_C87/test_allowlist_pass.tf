# S3.C87 (replication_source_check) - allowlist - COMPLIANT (0 findings)

# Authorized bucket replicating, named through a bucket reference
resource "aws_s3_bucket" "authsource" {
  bucket = "authorized-source-bucket"
}

resource "aws_s3_bucket_replication_configuration" "authsource" {
  bucket = aws_s3_bucket.authsource.id
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-replica"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"
    }
  }
}

# Unlisted bucket whose only replication rule is disabled
resource "aws_s3_bucket_replication_configuration" "paused" {
  bucket = "paused-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "paused"
    status = "Disabled"

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"
    }
  }
}
