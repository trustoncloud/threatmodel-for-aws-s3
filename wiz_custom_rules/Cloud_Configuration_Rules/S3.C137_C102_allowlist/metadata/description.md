# Description

Verify all associations of CloudFront distributions with buckets, access points, and/or Object Lambda Access Points are authorized (e.g., using the Macie finding: "Policy:IAMUser/S3BucketSharedWithCloudFront").

This rule covers two paired controls: the Terraform matcher implements S3.C137 (Directive); the cloud matcher verifies S3.C102 (Assurance).
