# Description

Verify all replicated buckets have metrics enabled on each replication rule (included by default in S3 RTC).

This rule covers two paired controls: the Terraform matcher implements S3.C134 (Directive); the cloud matcher verifies S3.C117 (Assurance).
