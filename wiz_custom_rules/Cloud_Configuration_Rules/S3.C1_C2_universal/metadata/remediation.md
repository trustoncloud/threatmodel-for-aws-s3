# Remediation

The service control policies (SCPs) attached to an organization root do not, between them, deny S3 requests without TLS or with TLS below 1.2. Add both Deny statements to an SCP on that root, each on all S3 actions and resources with no other condition than an optional `"aws:PrincipalIsAWSService": "false"` under `Bool` or `BoolIfExists`, so they cover every account. An SCP governs only your organization's principals, whose signed requests always carry that key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3WithoutTls",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyS3TlsBelow12",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": {
          "s3:TlsVersion": "1.2"
        }
      }
    }
  ]
}
```

`update-policy` replaces the whole content, so merge both statements into the current `Statement` list, saved as `scp.json`. Run these from the management account or a delegated administrator account:

```bash
aws organizations list-roots --query "Roots[].Id" --output text
aws organizations list-policies-for-target --target-id <root-id> --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id <policy-id> --query Policy.Content --output text
aws organizations update-policy --policy-id <policy-id> --content file://scp.json
aws organizations attach-policy --policy-id <policy-id> --target-id <root-id>
```

The check reads the SCPs that the Terraform source attaches to each root, together: one SCP may hold one Deny and another SCP on the same root the other. A literal root ID and an organization reference count as different roots, so attach to a root one way. SCPs attached to an OU or an account are not judged. An attachment whose target or policy content the source does not show is reported until it does. Replace `<root-id>` with the ID that `list-roots` returns and `<policy-id>` with the SCP to change.

## References

- [aws organizations list-roots](https://docs.aws.amazon.com/cli/latest/reference/organizations/list-roots.html)
- [aws organizations list-policies-for-target](https://docs.aws.amazon.com/cli/latest/reference/organizations/list-policies-for-target.html)
- [aws organizations describe-policy](https://docs.aws.amazon.com/cli/latest/reference/organizations/describe-policy.html)
- [aws organizations update-policy](https://docs.aws.amazon.com/cli/latest/reference/organizations/update-policy.html)
- [aws organizations attach-policy](https://docs.aws.amazon.com/cli/latest/reference/organizations/attach-policy.html)
- [Service control policies (SCPs)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Attaching organization policies with AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_policies_attach.html)
- [Actions, resources, and condition keys for Amazon S3](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html)
- [Security best practices for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the control blocking unencrypted requests and unauthorized TLS version(s) (e.g., the SCP on your root node); it should be detected.
