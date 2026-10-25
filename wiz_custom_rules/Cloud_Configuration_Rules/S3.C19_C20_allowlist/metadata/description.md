# Description

Verify all S3 VPC endpoints are blocking any IAM entity not belonging to authorized AWS Organizations, OUs, and/or AWS accounts.

This rule covers two paired controls: the Terraform matcher implements S3.C19 (Preventative); the cloud matcher verifies S3.C20 (Assurance).
