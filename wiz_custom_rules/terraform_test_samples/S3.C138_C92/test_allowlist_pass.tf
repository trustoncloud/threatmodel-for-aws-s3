# S3.C92 (replication_role_check) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket_replication_configuration" "authorized_role" {
  bucket = "source-bucket"
  role   = "arn:aws:iam::123456789012:role/authorized-replication-role"

  rule {
    id     = "replicate"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::any-replica-bucket"
    }
  }
}
