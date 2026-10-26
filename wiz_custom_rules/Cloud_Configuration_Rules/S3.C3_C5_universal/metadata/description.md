# Description

Verify a statement exists on all your VPC endpoint policies denying all requests with the condition "aws:SecureTransport" = False or using "s3:TlsVersion" != <i>authorized TLS version(s)</i>.

This rule covers two paired controls: the Terraform matcher implements S3.C3 (Preventative); the cloud matcher verifies S3.C5 (Assurance).
