# Description

Verify all objects in S3 buckets are encrypted with an authorized KMS key (e.g., using S3 Inventory or S3 Batch Operations, see <a href="https://aws.amazon.com/blogs/storage/encrypting-objects-with-amazon-s3-batch-operations/">blog</a>, or <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage_lens_basics_metrics_recommendations.html#storage_lens_basics_metrics_types">S3 Storage Lens</a>, UnencryptedObjectCount and SSEKMSEnabledBucketCount).

This rule covers two paired controls: the Terraform matcher implements S3.C140 (Directive); the cloud matcher verifies S3.C62 (Assurance).
