# Description

For buckets (or paths) requiring SSE-C, verify all buckets block PutObject requests with unauthorized encryption.

This rule covers two paired controls: the Terraform matcher implements S3.C146 (Preventative); the cloud matcher verifies S3.C147 (Assurance).
