# S3.C75 (bucket_object_lock_default) - allowlist - COMPLIANT (0 findings)

# WORM bucket with Object Lock and a COMPLIANCE default of 400 days in the standalone resource
resource "aws_s3_bucket" "records" {
  bucket              = "worm-records-bucket"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "records" {
  bucket = aws_s3_bucket.records.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 400
    }
  }
}

# WORM bucket with a GOVERNANCE default of 2 years (730 days) in the deprecated inline block
resource "aws_s3_bucket" "audit" {
  bucket = "worm-audit-bucket"

  object_lock_configuration {
    object_lock_enabled = "Enabled"

    rule {
      default_retention {
        mode  = "GOVERNANCE"
        years = 2
      }
    }
  }
}

# Object Lock enabled on an existing WORM bucket by the standalone resource alone, 1 year
resource "aws_s3_bucket_object_lock_configuration" "existing" {
  bucket = "worm-records-bucket"

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 1
    }
  }
}

# A period given by reference is known only at apply
variable "retention_days" {
  type = number
}

resource "aws_s3_bucket" "variable" {
  bucket              = "worm-records-bucket"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "variable" {
  bucket = aws_s3_bucket.variable.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
}

# A WORM bucket that is never created is not judged
resource "aws_s3_bucket" "nevermade" {
  count  = 0
  bucket = "worm-audit-bucket"
}

# A configuration that is never created is not judged
resource "aws_s3_bucket_object_lock_configuration" "nevermade" {
  for_each = {}
  bucket   = "worm-audit-bucket"

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 1
    }
  }
}

# Buckets not listed as requiring WORM are not assessed
resource "aws_s3_bucket" "unlisted" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket" "lookalike" {
  bucket = "worm-records-bucket-rogue"
}

resource "aws_s3_bucket" "shortlock" {
  bucket              = "example-short-lock-bucket"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "shortlock" {
  bucket = aws_s3_bucket.shortlock.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

# A bucket named only at apply cannot be matched with the list
resource "aws_s3_bucket" "generated" {
  bucket_prefix = "worm-"
}

# A dynamic block over a literal empty list generates nothing; the standalone configuration sets the default
resource "aws_s3_bucket" "emptydynamic" {
  bucket              = "worm-records-bucket"
  object_lock_enabled = true

  dynamic "object_lock_configuration" {
    for_each = []
    content {
      object_lock_enabled = "Enabled"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "emptydynamic" {
  bucket = aws_s3_bucket.emptydynamic.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}
