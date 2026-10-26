# S3.C88 (replication_configuration_check) - allowlist - VIOLATING

# Rule replicates to a destination not authorized for this bucket: 1 finding
resource "aws_s3_bucket_replication_configuration" "wrongdest" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "wrongdest"
    status = "Enabled"

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket = "arn:aws:s3:::rogue-replica-bucket"

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
}

# KMS route that does not replicate SSE-KMS objects: 1 finding
resource "aws_s3_bucket_replication_configuration" "nokmsobjects" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "nokmsobjects"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"

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
}

# KMS route encrypting replicas with another key: 1 finding
resource "aws_s3_bucket_replication_configuration" "wrongkey" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "wrongkey"
    status = "Enabled"

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"

      encryption_configuration {
        replica_kms_key_id = "arn:aws:kms:us-west-2:999999999999:key/other-key"
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
}

# Owner override the route does not expect: 1 finding
resource "aws_s3_bucket_replication_configuration" "ownerswap" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "ownerswap"
    status = "Enabled"

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"
      account = "444455556666"

      access_control_translation {
        owner = "Destination"
      }

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
}

# Route requiring RTC without it: 1 finding
resource "aws_s3_bucket_replication_configuration" "nortc" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "nortc"
    status = "Enabled"

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"

      encryption_configuration {
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"
      }
    }
  }
}
