# Description

Verify all S3 bucket policies block unencrypted traffic (e.g., using the AWS Config rule: <a href="https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html">S3_BUCKET_SSL_REQUESTS_ONLY</a>) and unauthorized versions of TLS.

This rule covers two paired controls: the Terraform matcher implements S3.C6 (Preventative); the cloud matcher verifies S3.C7 (Assurance).
