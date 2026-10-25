# S3.C87 (replication_source_check) - allowlist - VIOLATING

# Unlisted bucket replicating, named as a literal: 1 finding
resource "aws_s3_bucket_replication_configuration" "rogue" {
  bucket = "rogue-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-replica"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"
    }
  }
}

# Unlisted bucket replicating, named through a bucket reference: 1 finding
resource "aws_s3_bucket" "unlisted" {
  bucket = "unlisted-source-bucket"
}

resource "aws_s3_bucket_replication_configuration" "unlisted" {
  bucket = aws_s3_bucket.unlisted.id
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-replica"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"
    }
  }
}
