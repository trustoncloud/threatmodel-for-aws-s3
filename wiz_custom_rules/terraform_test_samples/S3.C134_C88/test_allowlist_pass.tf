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

variable "example_kms_objects_status" {
  type    = string
  default = "Enabled"
}

variable "example_replication_time_status" {
  type    = string
  default = "Enabled"
}

variable "example_metrics_status" {
  type    = string
  default = "Enabled"
}

# Values given by reference resolve at apply time; the cloud matcher judges them.
resource "aws_s3_bucket_replication_configuration" "status_by_reference" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-replica-by-reference"
    status = "Enabled"

    filter {
      prefix = "data/"
    }

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = var.example_kms_objects_status
      }
    }

    destination {
      bucket = "arn:aws:s3:::authorized-replica-bucket"

      encryption_configuration {
        replica_kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key"
      }

      replication_time {
        status = var.example_replication_time_status
        time {
          minutes = 15
        }
      }

      metrics {
        status = var.example_metrics_status
        event_threshold {
          minutes = 15
        }
      }
    }
  }
}

variable "example_inline_kms_objects_enabled" {
  type    = bool
  default = true
}

# Both authorized routes configured as expected in the inline
# replication_configuration block. The replica key sits on the destination,
# SSE-KMS objects are selected with `enabled`, and metrics and
# replication_time blocks without a status are Enabled by default. The third
# rule selects SSE-KMS objects by reference, known only at apply.
resource "aws_s3_bucket" "authsrc_inline" {
  bucket = "authorized-source-bucket"

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"

    rules {
      id       = "to-replica"
      priority = 1
      status   = "Enabled"

      filter {
        prefix = "data/"
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
          minutes = 15
        }
      }
    }

    rules {
      id       = "to-archive"
      priority = 2
      status   = "Enabled"

      filter {
        prefix = "logs/"
      }

      destination {
        bucket = "arn:aws:s3:::authorized-archive-bucket"
      }
    }

    rules {
      id       = "to-replica-by-reference"
      priority = 3
      status   = "Enabled"

      filter {
        prefix = "ref/"
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          enabled = var.example_inline_kms_objects_enabled
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
  }
}

# An inline block on a bucket not on the list is S3.C87's finding, not this rule's
resource "aws_s3_bucket" "othersrc_inline" {
  bucket = "other-inline-source-bucket"

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"

    rules {
      id     = "to-rogue"
      status = "Enabled"

      destination {
        bucket = "arn:aws:s3:::rogue-replica-bucket"
      }
    }
  }
}

# Never created (count 0, an empty for_each): not judged, though the
# destination is not authorized
resource "aws_s3_bucket_replication_configuration" "count_zero" {
  count  = 0
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-rogue"
    status = "Enabled"

    destination {
      bucket = "arn:aws:s3:::rogue-replica-bucket"
    }
  }
}

resource "aws_s3_bucket" "for_each_empty_inline" {
  for_each = {}
  bucket   = "authorized-source-bucket"

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"

    rules {
      id     = "to-rogue"
      status = "Enabled"

      destination {
        bucket = "arn:aws:s3:::rogue-replica-bucket"
      }
    }
  }
}

variable "example_replication_rules" {
  type = list(object({ id = string, destination_bucket = string }))
  default = [
    {
      id                 = "to-archive"
      destination_bucket = "arn:aws:s3:::authorized-archive-bucket"
    },
  ]
}

# Rules generated by a dynamic block on a bucket not on the list are
# S3.C87's finding, not this rule's
resource "aws_s3_bucket_replication_configuration" "dyn_othersrc" {
  bucket = "other-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  dynamic "rule" {
    for_each = var.example_replication_rules

    content {
      id     = rule.value.id
      status = "Enabled"

      destination {
        bucket = rule.value.destination_bucket
      }
    }
  }
}

variable "example_metrics_statuses" {
  type    = list(string)
  default = ["Enabled"]
}

# A metrics block generated by a dynamic block on a route that does not
# require Replication Time Control: the route does not need it, so it is not
# read
resource "aws_s3_bucket_replication_configuration" "dyn_archive_metrics" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-archive"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket = "arn:aws:s3:::authorized-archive-bucket"

      dynamic "metrics" {
        for_each = var.example_metrics_statuses

        content {
          status = metrics.value
        }
      }
    }
  }
}

# A dynamic block whose for_each is a literal empty collection generates
# nothing and is read as absent: the archive route of an authorized
# bucket, with an empty dynamic rule and an empty dynamic
# access_control_translation, so replica ownership is unchanged
resource "aws_s3_bucket_replication_configuration" "nodyn_archive" {
  bucket = "authorized-source-bucket"
  role   = "arn:aws:iam::123456789012:role/replication-role"

  rule {
    id     = "to-archive"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket = "arn:aws:s3:::authorized-archive-bucket"

      dynamic "access_control_translation" {
        for_each = []

        content {
          owner = "Destination"
        }
      }
    }
  }

  dynamic "rule" {
    for_each = []

    content {
      id     = "generated"
      status = "Enabled"

      destination {
        bucket = "arn:aws:s3:::rogue-replica-bucket"
      }
    }
  }
}
