# Description

Verify all general purpose buckets use their authorized ABAC configuration.

This rule implements S3.C171 (Directive) through its Terraform matcher; S3.C172 is the paired Assurance control (no runtime scan surface).

Because it has no cloud matcher it carries no target native type, so it will not appear while a Native Type filter is applied and it reports no cloud findings. Filter on 'Created by equals User' or 'Target Platform equals Terraform' to see it.
