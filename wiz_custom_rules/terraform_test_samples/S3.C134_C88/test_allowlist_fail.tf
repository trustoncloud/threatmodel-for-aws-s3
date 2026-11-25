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

# Inline replication_configuration block with one wrong setting per rule: 5 findings
resource "aws_s3_bucket" "inline_routes" {
  bucket = "authorized-source-bucket"

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"

    # Lookalike of an authorized destination
    rules {
      id       = "inline-wrongdest"
      priority = 1
      status   = "Enabled"

      filter {
        prefix = "a/"
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          enabled = true
        }
      }

      destination {
        bucket             = "arn:aws:s3:::authorized-replica-bucket-rogue"
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"

        replication_time {
          status  = "Enabled"
          minutes = 15
        }

        metrics {
          status  = "Enabled"
          minutes = 15
        }
      }
    }

    # KMS route that does not replicate SSE-KMS objects
    rules {
      id       = "inline-nokmsobjects"
      priority = 2
      status   = "Enabled"

      filter {
        prefix = "b/"
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          enabled = false
        }
      }

      destination {
        bucket             = "arn:aws:s3:::authorized-replica-bucket"
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"

        replication_time {
          status  = "Enabled"
          minutes = 15
        }

        metrics {
          status  = "Enabled"
          minutes = 15
        }
      }
    }

    # KMS route encrypting replicas with another key
    rules {
      id       = "inline-wrongkey"
      priority = 3
      status   = "Enabled"

      filter {
        prefix = "c/"
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          enabled = true
        }
      }

      destination {
        bucket             = "arn:aws:s3:::authorized-replica-bucket"
        replica_kms_key_id = "arn:aws:kms:us-west-2:999999999999:key/other-key"

        replication_time {
          status  = "Enabled"
          minutes = 15
        }

        metrics {
          status  = "Enabled"
          minutes = 15
        }
      }
    }

    # Owner override the route does not expect
    rules {
      id       = "inline-ownerswap"
      priority = 4
      status   = "Enabled"

      filter {
        prefix = "d/"
      }

      destination {
        bucket     = "arn:aws:s3:::authorized-archive-bucket"
        account_id = "444455556666"

        access_control_translation {
          owner = "Destination"
        }
      }
    }

    # Route requiring RTC with metrics turned off
    rules {
      id       = "inline-nortc"
      priority = 5
      status   = "Enabled"

      filter {
        prefix = "e/"
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          enabled = true
        }
      }

      destination {
        bucket             = "arn:aws:s3:::authorized-replica-bucket"
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"

        replication_time {
          minutes = 15
        }

        metrics {
          status  = "Disabled"
          minutes = 15
        }
      }
    }
  }
}

# Unauthorized destination on a configuration created through count: 1 finding
resource "aws_s3_bucket_replication_configuration" "count_one" {
  count  = 1
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "counted-wrongdest"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::rogue-replica-bucket"
    }
  }
}

variable "example_unknown_replication_rules" {
  type = list(object({ id = string, destination_bucket = string }))
}

variable "example_replication_configuration" {
  type = list(object({ role = string, destination_bucket = string }))
}

# Authorized bucket whose replication rules are generated by a dynamic block,
# which cannot be checked against its routes: in the standalone resource, in
# the inline block, and as a whole inline block: 3 findings
resource "aws_s3_bucket_replication_configuration" "dyn_standalone" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  dynamic "rule" {
    for_each = var.example_unknown_replication_rules

    content {
      id     = rule.value.id
      status = "Enabled"

      destination {
        bucket = rule.value.destination_bucket
      }
    }
  }
}

resource "aws_s3_bucket" "dyn_rules_inline" {
  bucket = "authorized-source-bucket"

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"

    dynamic "rules" {
      for_each = var.example_unknown_replication_rules

      content {
        id     = rules.value.id
        status = "Enabled"

        destination {
          bucket = rules.value.destination_bucket
        }
      }
    }
  }
}

resource "aws_s3_bucket" "dyn_whole" {
  bucket = "authorized-source-bucket"

  dynamic "replication_configuration" {
    for_each = var.example_replication_configuration

    content {
      role = replication_configuration.value.role

      rules {
        id     = "to-replica"
        status = "Enabled"

        destination {
          bucket = replication_configuration.value.destination_bucket
        }
      }
    }
  }
}

# Rule whose destination is generated by a dynamic block: 1 finding
resource "aws_s3_bucket_replication_configuration" "dyn_destination" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "dynamic-destination"
    status = "Enabled"

    filter {
      prefix = "data/"
    }

    delete_marker_replication {
      status = "Disabled"
    }

    dynamic "destination" {
      for_each = var.example_unknown_replication_rules

      content {
        bucket = destination.value.destination_bucket
      }
    }
  }
}

variable "example_unknown_metrics_statuses" {
  type = list(string)
}

# Route requiring Replication Time Control whose metrics block is generated by
# a dynamic block, in the standalone resource and in the inline block: 2
# findings
resource "aws_s3_bucket_replication_configuration" "dyn_rtc_metrics" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "dynamic-metrics"
    status = "Enabled"

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

      dynamic "metrics" {
        for_each = var.example_unknown_metrics_statuses

        content {
          status = metrics.value
        }
      }
    }
  }
}

resource "aws_s3_bucket" "dyn_inline_metrics" {
  bucket = "authorized-source-bucket"

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"

    rules {
      id     = "dynamic-inline-metrics"
      status = "Enabled"

      source_selection_criteria {
        sse_kms_encrypted_objects {
          enabled = true
        }
      }

      destination {
        bucket             = "arn:aws:s3:::authorized-replica-bucket"
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"

        replication_time {
          minutes = 15
        }

        dynamic "metrics" {
          for_each = var.example_unknown_metrics_statuses

          content {
            status = metrics.value
          }
        }
      }
    }
  }
}
