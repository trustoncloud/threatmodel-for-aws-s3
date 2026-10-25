# S3.C88 (replication_configuration_check) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket" "authsrc" {
  bucket = "authorized-source-bucket"
}

resource "aws_s3_bucket" "replicadest" {
  bucket = "authorized-replica-bucket"
}

# Both authorized routes configured as expected; the replica destination is a
# bucket reference
resource "aws_s3_bucket_replication_configuration" "authsrc" {
  bucket = aws_s3_bucket.authsrc.id
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id       = "to-replica"
    priority = 1
    status   = "Enabled"

    filter {
      prefix = "data/"
    }

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket = aws_s3_bucket.replicadest.arn

      encryption_configuration {
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"
      }

      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }

      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }
  }

  rule {
    id       = "to-archive"
    priority = 2
    status   = "Enabled"

    filter {
      prefix = "logs/"
    }

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket = "arn:aws:s3:::authorized-archive-bucket"
    }
  }
}

# A bucket not on the list is S3.C87's finding, not this rule's
resource "aws_s3_bucket_replication_configuration" "othersrc" {
  bucket = "other-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-rogue"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::rogue-replica-bucket"
    }
  }
}
