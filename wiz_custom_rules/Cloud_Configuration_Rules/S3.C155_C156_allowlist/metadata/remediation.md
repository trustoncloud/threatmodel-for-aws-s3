# Remediation

The bucket in the finding has no bucket policy Deny that blocks every AWS service-linked role, or its Deny exempts a role that is not authorized. Add this Deny, which blocks every role under `role/aws-service-role/` except the exempted ones:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyServiceLinkedRoles",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::<bucket-name>",
        "arn:aws:s3:::<bucket-name>/*"
      ],
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
        },
        "ArnNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::<account-id>:role/aws-service-role/<service-principal>/<role-name>"
          ]
        }
      }
    }
  ]
}
```

`put-bucket-policy` replaces the whole policy, so merge the statement into the current one, saved as `policy.json`, or use the document above if the bucket has none:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

Write `*` for the account and the bucket's partition (or `*`) for the partition. The pattern must cover everything under `role/aws-service-role/`, or name roles by `AWSServiceRoleFor` as in `"arn:aws:iam::*:*/AWSServiceRoleFor*"`; a pattern for one service or one account does not count. A Deny for every principal that only exempts roles also counts. Only `aws:PrincipalArn` may appear in the condition. Drop the `ArnNotEquals` block if no service-linked role needs the bucket. If an exempted role is approved, add its ARN to `authorized_service_roles` instead; that list authorizes the role on every assessed bucket. Replace `<bucket-name>` with the bucket in the finding and `arn:aws:iam::<account-id>:role/aws-service-role/<service-principal>/<role-name>` with each authorized role ARN.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Bucket policies for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [Examples of Amazon S3 bucket policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [AWS global condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- [AWS account root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Remove the statement on a bucket policy denying all unauthorized service roles; it should be detected.
