# Description

Verify account-level S3 Block Public Access is enabled on all AWS accounts, with BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets set to true (e.g., using the AWS Config rule: <a href="https://docs.aws.amazon.com/config/latest/developerguide/s3-account-level-public-access-blocks.html">S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS</a>).

This rule covers two paired controls: the Terraform matcher implements S3.C49 (Directive); the cloud matcher verifies S3.C50 (Assurance).
