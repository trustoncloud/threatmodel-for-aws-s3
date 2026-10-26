# S3.C117 (replication_metrics_enabled) - universal - VIOLATING

# Rule with metrics disabled + rule with no metrics block: 2 findings
resource "aws_s3_bucket_replication_configuration" "without_metrics" {
  bucket = "source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "metrics-disabled"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::replica-bucket"

      metrics {
        status = "Disabled"
      }
    }
  }

  rule {
    id     = "metrics-missing"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::replica-bucket-2"
    }
  }
}
