# S3.C62 (bucket_default_kms_key) - allowlist - VIOLATING

# No default encryption configuration: S3 uses SSE-S3: 1 finding
resource "aws_s3_bucket" "unencrypted" {
  bucket = "example-plain-bucket"
}

# SSE-S3 in the standalone configuration: 1 finding
resource "aws_s3_bucket" "aesonly" {
  bucket = "example-sses3-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aesonly" {
  bucket = aws_s3_bucket.aesonly.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SSE-KMS with no key: S3 uses the AWS managed key aws/s3: 1 finding
resource "aws_s3_bucket" "awsmanaged" {
  bucket = "example-awsmanaged-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "awsmanaged" {
  bucket = aws_s3_bucket.awsmanaged.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# SSE-KMS with an empty key: 1 finding
resource "aws_s3_bucket" "emptykmskey" {
  bucket = "example-emptykey-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "emptykmskey" {
  bucket = aws_s3_bucket.emptykmskey.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = ""
    }
  }
}

# A rule that sets only blocked_encryption_types leaves SSE-S3: 1 finding
resource "aws_s3_bucket" "blockonly" {
  bucket = "example-blockonly-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "blockonly" {
  bucket = aws_s3_bucket.blockonly.id

  rule {
    blocked_encryption_types = ["SSE-C"]
  }
}

# The authorized key ID in another account: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "otheraccount" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:210987654321:key/authorized-key"
    }
  }
}

# The authorized key ID in another Region: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "otherregion" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-west-2:123456789012:key/authorized-key"
    }
  }
}

# The authorized key ID in another partition: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "otherpartition" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws-us-gov:kms:us-east-1:123456789012:key/authorized-key"
    }
  }
}

# An alias ARN of the authorized key: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "aliasarn" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:alias/authorized-key"
    }
  }
}

# A key ID that starts like the authorized one: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "roguesuffix" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/authorized-key-rogue"
    }
  }
}

# An alias without an ARN resolves in the uploader's account: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "barealias" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/authorized-key"
    }
  }
}

# A listed bucket using the shared key instead of its own: 1 finding
resource "aws_s3_bucket" "financeshared" {
  bucket = "finance-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "financeshared" {
  bucket = aws_s3_bucket.financeshared.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
    }
  }
}

# A key listed only for finance-data-bucket used on another bucket: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "borrowedkey" {
  bucket = "example-kms-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }
}

# A bucket named like a listed one uses that bucket's key: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "lookalikename" {
  bucket = "finance-data-bucket-rogue"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }
}

# A bucket named only at apply with a key listed for no bucket: 1 finding
resource "aws_s3_bucket" "generated" {
  bucket_prefix = "example-generated-"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "generated" {
  bucket = aws_s3_bucket.generated.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/unlisted-key"
    }
  }
}

# Deprecated inline block with SSE-S3: 1 finding
resource "aws_s3_bucket" "inlinesses3" {
  bucket = "example-inline-sses3-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# Deprecated inline block with SSE-KMS and no key: 1 finding
resource "aws_s3_bucket" "inlinenokey" {
  bucket = "example-inline-nokey-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

# Deprecated inline block with an unauthorized key: 1 finding
resource "aws_s3_bucket" "inlinewrong" {
  bucket = "example-inline-wrong-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/unlisted-key"
      }
    }
  }
}

# The bucket's only configuration is never created, so S3 uses SSE-S3: 1 finding
resource "aws_s3_bucket" "ghostconfig" {
  bucket = "example-ghost-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ghostconfig" {
  count  = 0
  bucket = aws_s3_bucket.ghostconfig.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/authorized-key"
    }
  }
}

# An object uploaded with SSE-S3: 1 finding
resource "aws_s3_object" "objsses3" {
  bucket                 = "example-kms-bucket"
  key                    = "objsses3.txt"
  source                 = "objsses3.txt"
  server_side_encryption = "AES256"
}

# An object uploaded with SSE-KMS and no key: 1 finding
resource "aws_s3_object" "objnokey" {
  bucket                 = "example-kms-bucket"
  key                    = "objnokey.txt"
  source                 = "objnokey.txt"
  server_side_encryption = "aws:kms"
}

# An object copied with an unauthorized key: 1 finding
resource "aws_s3_object_copy" "copywrong" {
  bucket                 = "example-kms-bucket"
  key                    = "copywrong.txt"
  source                 = "example-kms-bucket/objnokey.txt"
  server_side_encryption = "aws:kms"
  kms_key_id             = "arn:aws:kms:us-east-1:210987654321:key/authorized-key"
}

# An object in the deprecated resource with an unauthorized key: 1 finding
resource "aws_s3_bucket_object" "legacyobj" {
  bucket     = "example-kms-bucket"
  key        = "legacyobj.txt"
  source     = "legacyobj.txt"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/unlisted-key"
}

# A bucket named like one approved for SSE-S3 keeps SSE-S3: 1 finding
resource "aws_s3_bucket" "logslookalike" {
  bucket = "example-access-logs-bucket-2"
}

# A bucket approved for SSE-S3 using the AWS managed key aws/s3: 1 finding
resource "aws_s3_bucket_server_side_encryption_configuration" "logsmanaged" {
  bucket = "example-access-logs-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# Default encryption generated by a dynamic block cannot be read: 1 finding each
resource "aws_s3_bucket" "dynwholeblock" {
  bucket = "example-dynamic-block-bucket"

  dynamic "server_side_encryption_configuration" {
    for_each = ["on"]
    content {
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm = "AES256"
        }
      }
    }
  }
}

resource "aws_s3_bucket" "dyninlinerule" {
  bucket = "example-dynamic-inline-bucket"

  server_side_encryption_configuration {
    dynamic "rule" {
      for_each = ["aws:kms"]
      content {
        apply_server_side_encryption_by_default {
          sse_algorithm = rule.value
        }
      }
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dynrulecfg" {
  bucket = "example-kms-bucket"

  dynamic "rule" {
    for_each = ["aws:kms"]
    content {
      apply_server_side_encryption_by_default {
        sse_algorithm = rule.value
      }
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dynapplyblock" {
  bucket = "example-kms-bucket"

  rule {
    dynamic "apply_server_side_encryption_by_default" {
      for_each = ["aws:kms"]
      content {
        sse_algorithm = apply_server_side_encryption_by_default.value
      }
    }
  }
}

# An object copied with SSE-C (a customer-provided key): 1 finding
resource "aws_s3_object_copy" "copysseckey" {
  bucket             = "example-kms-bucket"
  key                = "copysseckey.txt"
  source             = "example-kms-bucket/objnokey.txt"
  customer_algorithm = "AES256"
  customer_key       = "EXAMPLEKEY0123456789EXAMPLEKEY01"
}

# An object copied with SSE-C named only by the key digest: 1 finding
resource "aws_s3_object_copy" "copyssecdigest" {
  bucket           = "example-kms-bucket"
  key              = "copyssecdigest.txt"
  source           = "example-kms-bucket/objnokey.txt"
  customer_key_md5 = "EXAMPLEDIGEST0123456789="
}
