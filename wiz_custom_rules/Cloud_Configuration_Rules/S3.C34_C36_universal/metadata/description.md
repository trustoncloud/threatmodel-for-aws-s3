# Description

Verify the control blocking change ObjectACL to public (e.g., an SCP and VPC endpoint policy) is properly implemented.

This rule covers two paired controls: the Terraform matcher implements S3.C34 (Preventative); the cloud matcher verifies S3.C36 (Assurance).
