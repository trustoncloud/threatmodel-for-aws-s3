# S3.C117 (replication_metrics_enabled) - universal - COMPLIANT (0 findings)

resource "aws_s3_bucket_replication_configuration" "with_metrics" {
  bucket = "source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "replicate-with-metrics"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::replica-bucket"

      metrics {
        status = "Enabled"

        event_threshold {
          minutes = 15
        }
      }
    }
  }
}
