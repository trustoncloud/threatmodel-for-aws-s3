# S3.C62 (bucket_default_kms_key) - allowlist - COMPLIANT (0 findings)

# SSE-KMS with an authorized key ARN in the standalone configuration
resource "aws_s3_bucket" "kmsdefault" {
  bucket = "example-kms-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kmsdefault" {
  bucket = aws_s3_bucket.kmsdefault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
    }
    bucket_key_enabled = true
  }
}

# A listed bucket with its own key, named by its literal bucket name
resource "aws_s3_bucket" "financeown" {
  bucket = "finance-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "financeown" {
  bucket = "finance-data-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }
}

# DSSE-KMS with an authorized key in the deprecated inline block
resource "aws_s3_bucket" "inlinedsse" {
  bucket = "example-inline-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms:dsse"
        kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
      }
    }
  }
}

# A key given by reference is known only at apply and is left to the cloud check
resource "aws_kms_key" "bucketkey" {
  description = "Default encryption key for example-reference-bucket"
}

resource "aws_s3_bucket" "keyreference" {
  bucket = "example-reference-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "keyreference" {
  bucket = aws_s3_bucket.keyreference.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucketkey.arn
    }
  }
}

# A key ID without an ARN is read by the cloud check, in the bucket's account and Region
resource "aws_s3_bucket" "keyidonly" {
  bucket = "example-keyid-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "keyidonly" {
  bucket = aws_s3_bucket.keyidonly.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }
}

# A bucket named only at apply with a key listed for a bucket: left to the cloud check
resource "aws_s3_bucket" "prefixed" {
  bucket_prefix = "example-generated-"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prefixed" {
  bucket = aws_s3_bucket.prefixed.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }
}

# A bucket and a configuration that are never created are not judged
resource "aws_s3_bucket" "nevermade" {
  count  = 0
  bucket = "example-nevermade-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "nevermade" {
  for_each = toset([])
  bucket   = "example-nevermade-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Objects that take the bucket default, or name an authorized key
resource "aws_s3_object" "inherits" {
  bucket = aws_s3_bucket.kmsdefault.id
  key    = "inherits.txt"
  source = "inherits.txt"
}

resource "aws_s3_object" "objectkey" {
  bucket                 = aws_s3_bucket.kmsdefault.id
  key                    = "objectkey.txt"
  source                 = "objectkey.txt"
  server_side_encryption = "aws:kms"
  kms_key_id             = "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
}

resource "aws_s3_object_copy" "copiedkey" {
  bucket     = "finance-data-bucket"
  key        = "copiedkey.txt"
  source     = "example-kms-bucket/objectkey.txt"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}

# A bucket approved for SSE-S3 keeps the S3 default, or sets SSE-S3, and its objects may use SSE-S3
resource "aws_s3_bucket" "accesslogs" {
  bucket = "example-access-logs-bucket"
}

resource "aws_s3_bucket" "logsexplicit" {
  bucket = "example-access-logs-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logsexplicit" {
  bucket = aws_s3_bucket.logsexplicit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "logobject" {
  bucket                 = aws_s3_bucket.accesslogs.id
  key                    = "logobject.txt"
  source                 = "logobject.txt"
  server_side_encryption = "AES256"
}

# A dynamic block over a literal empty list generates nothing; the standalone configuration sets the key
resource "aws_s3_bucket" "emptydynamic" {
  bucket = "example-empty-dynamic-bucket"

  dynamic "server_side_encryption_configuration" {
    for_each = []
    content {
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm = "AES256"
        }
      }
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "emptydynamic" {
  bucket = aws_s3_bucket.emptydynamic.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
    }
  }
}
