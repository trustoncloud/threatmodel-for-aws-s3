# Description

Verify all buckets block PutObject requests with an unauthorized KMS key (e.g., using the Config rule: <a href="https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy-not-more-permissive.html">S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE</a>, note that a new rule needs to be deployed for each configuration, then the resource tracked by name or tag; alternatively, you might use <a href="https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-server-side-encryption-enabled.html">S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED</a> to ensure limited coverage).

This rule covers two paired controls: the Terraform matcher implements S3.C66 (Preventative); the cloud matcher verifies S3.C67 (Assurance).
