# Description

Verify only authorized IAM principals allowed to access via bucket policy are used (e.g., using the AWS Config rule <a href="https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy-grantee-check.html">S3_BUCKET_POLICY_GRANTEE_CHECK</a>).

This rule covers two paired controls: the Terraform matcher implements S3.C150 (Directive); the cloud matcher verifies S3.C151 (Assurance).
