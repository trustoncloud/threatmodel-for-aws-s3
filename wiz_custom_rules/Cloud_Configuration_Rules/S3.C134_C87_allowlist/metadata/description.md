# Description

Verify only authorized buckets have replication enabled with their correct configuration (e.g., using <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage_lens_metrics_glossary.html">S3 Storage Lens</a> CrossAccountReplicationRuleCount).

This rule covers two paired controls: the Terraform matcher implements S3.C134 (Directive); the cloud matcher verifies S3.C87 (Assurance).
