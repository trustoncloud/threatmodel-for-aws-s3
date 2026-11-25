# Remediation

The S3 VPC endpoint in the finding lets callers make objects public through an object ACL. Deny `s3:PutObjectAcl` and `s3:PutObjectVersionAcl` requests that set a public canned ACL, or that name the `AllUsers` or `AuthenticatedUsers` group in a grant header, with each header in its own statement:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
    {"Sid": "DenyPublicCannedAcl", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}}},
    {"Sid": "DenyPublicGrantRead", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}},
    {"Sid": "DenyPublicGrantReadAcp", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}},
    {"Sid": "DenyPublicGrantWriteAcp", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}},
    {"Sid": "DenyPublicGrantFullControl", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}}
  ]
}
```

The full-access Allow stands in for your own Allow statements. `modify-vpc-endpoint` replaces the whole policy, so merge the Denies into the current one, saved as `policy.json`:

```bash
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <vpce-id> --query "VpcEndpoints[0].PolicyDocument" --output text
aws ec2 modify-vpc-endpoint --vpc-endpoint-id <vpce-id> --policy-document file://policy.json
```

Keep each Deny as broad as shown, with its header test as the only condition and no `NotPrincipal`, `NotAction` or `NotResource` element. A statement that tests two headers denies only requests that carry both, so keep the headers apart. A grant header can list several grantees, so match each group with a `StringLike` pattern that starts and ends with `*`. The Denies also block uploads that set a public ACL.

The rule checks the request headers only. A `PutObjectAcl` request can also carry the ACL in its XML body, which these condition keys do not show, so the rule does not establish that such a request is denied. S3 Block Public Access (`BlockPublicAcls` and `IgnorePublicAcls`), or ACLs disabled through bucket owner enforced Object Ownership, stops public ACLs in every form. Only this endpoint's traffic is checked: cover other routes with the same Denies in a service control policy. Replace `<vpce-id>` with the endpoint in the finding.

## References

- [aws ec2 describe-vpc-endpoints](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html)
- [aws ec2 modify-vpc-endpoint](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-vpc-endpoint.html)
- [Control access to VPC endpoints using endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)
- [Access control list (ACL) overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
- [Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Controlling ownership of objects and disabling ACLs for your bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the control blocking changes of ObjectACL to public; it should be detected.
