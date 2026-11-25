Add Deny statements to the S3 endpoint's policy, on every principal and object, for `s3:PutObjectAcl` and `s3:PutObjectVersionAcl`: one when `s3:x-amz-acl` is `public-read`, `public-read-write` or `authenticated-read`, and one for each grant header that names the `AllUsers` or `AuthenticatedUsers` group, each with that test as its only condition. The policy goes in `policy` or an attached `aws_vpc_endpoint_policy`, as JSON or from an `aws_iam_policy_document`; an endpoint with neither keeps the full-access default and is reported.

```hcl
resource "aws_vpc_endpoint" "example" {
  service_name = "com.amazonaws.<region>.s3"
  policy       = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
    {"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}}},
    {"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-read": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}},
    {"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-read-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}},
    {"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-write-acp": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}},
    {"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectAcl", "s3:PutObjectVersionAcl"], "Resource": "arn:aws:s3:::*/*",
     "Condition": {"StringLike": {"s3:x-amz-grant-full-control": ["*http://acs.amazonaws.com/groups/global/AllUsers*", "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"]}}}
  ]
}
POLICY
}
```

Statements may split the actions, canned ACLs and groups between them. A grant pattern must start and end with `*`, since a header can list other grantees around the group. Only request headers are checked: an ACL sent in the request body needs S3 Block Public Access or ACLs disabled through Object Ownership.

## References

- [aws_vpc_endpoint (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/vpc_endpoint)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
