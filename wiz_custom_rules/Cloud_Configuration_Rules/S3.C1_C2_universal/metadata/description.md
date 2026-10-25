# Description

Verify the control blocking unencrypted requests and unauthorized TLS versions from IAM entities you control (e.g., an SCP on your AWS Organization's root node) is properly implemented.

This rule implements S3.C1 (Preventative) through its Terraform matcher; S3.C2 is the paired Assurance control (no runtime scan surface).

Because it has no cloud matcher it carries no target native type, so it will not appear while a Native Type filter is applied and it reports no cloud findings. Filter on 'Created by equals User' or 'Target Platform equals Terraform' to see it.
