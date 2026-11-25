# Remediation

The S3 VPC endpoint in the finding admits callers from any organization. Add a Deny that refuses every S3 request from outside yours:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "DenyOutsideOrganization",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "<org-id>"
        }
      }
    }
  ]
}
```

The full-access Allow stands in for your own Allow statements. `modify-vpc-endpoint` replaces the whole policy, so merge the Deny into the current one, saved as `policy.json`:

```bash
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <vpce-id> --query "VpcEndpoints[0].PolicyDocument" --output text
aws ec2 modify-vpc-endpoint --vpc-endpoint-id <vpce-id> --policy-document file://policy.json
```

Keep the Deny as broad as shown, with the organization test as its only condition and no `NotPrincipal`, `NotAction` or `NotResource` element. Testing `aws:PrincipalAccount` with `StringNotEquals`, or `aws:PrincipalOrgPaths` with `ForAllValues:StringNotLike`, also counts. It also refuses anonymous requests, such as public bucket downloads, so check that nothing in the VPC needs them. Replace `<vpce-id>` with the endpoint in the finding and `<org-id>` with your organization ID.

## References

- [aws ec2 describe-vpc-endpoints](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html)
- [aws ec2 modify-vpc-endpoint](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-vpc-endpoint.html)
- [Control access to VPC endpoints using endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)
- [Gateway endpoints for Amazon S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)
- [AWS global condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the policy statement blocking any IAM entity not belonging to authorized AWS Organizations, OUs, and/or AWS accounts from the VPC endpoint; it should be detected.
