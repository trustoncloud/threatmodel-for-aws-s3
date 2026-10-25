# Description

Verify all buckets include a control to limit access to only authorized VPCs (e.g., using the AWS Config rule <a href="https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy-grantee-check.html">S3_BUCKET_POLICY_GRANTEE_CHECK</a>).

This rule covers two paired controls: the Terraform matcher implements S3.C99 (Preventative); the cloud matcher verifies S3.C100 (Assurance).
