# S3.C92 (replication_role_check) - allowlist - VIOLATING

# Replication using an unauthorized IAM role: 1 finding
resource "aws_s3_bucket_replication_configuration" "rogue_role" {
  bucket = "source-bucket"
  role   = "arn:aws:iam::999999999999:role/rogue-replication-role"

  rule {
    id     = "replicate"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::any-replica-bucket"
    }
  }
}
