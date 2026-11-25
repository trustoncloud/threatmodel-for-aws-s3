# Remediation

The access point in the finding targets a bucket or bucket owner account that is not authorized. Its bucket, network origin and Block Public Access settings cannot be changed, so record its settings and policy, delete it and, if still needed, create it again on an authorized bucket:

```bash
aws s3control get-access-point --account-id <account-id> --name <access-point-name>
aws s3control get-access-point-policy --account-id <account-id> --name <access-point-name> --query Policy --output text > policy.json
aws s3control delete-access-point --account-id <account-id> --name <access-point-name>
aws s3control create-access-point --account-id <account-id> --name <access-point-name> --bucket <bucket-name> --bucket-account-id <bucket-account-id> --vpc-configuration VpcId=<vpc-id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3control put-access-point-policy --account-id <account-id> --name <access-point-name> --policy file://policy.json
```

Give `--vpc-configuration` the `VpcId` that `get-access-point` shows; leave it out only when `NetworkOrigin` is `Internet`, since without it the new access point's origin is `Internet`. Set the four Block Public Access values it shows. Delete the access point only once its policy is in policy.json; when it has none, `get-access-point-policy` reports that, and you skip `put-access-point-policy`. The new access point gets a new alias, so update clients that use it. Access points in their bucket's account are checked too. If the bucket and its owner are approved, add the bucket name to `authorized_buckets` and the account ID to `authorized_accounts` instead. Replace `<account-id>` and `<access-point-name>` with the access point's account and name, `<bucket-name>` and `<bucket-account-id>` with an authorized bucket and its owner account, and `<vpc-id>` with the VPC it showed.

## References

- [aws s3control get-access-point](https://docs.aws.amazon.com/cli/latest/reference/s3control/get-access-point.html)
- [aws s3control get-access-point-policy](https://docs.aws.amazon.com/cli/latest/reference/s3control/get-access-point-policy.html)
- [aws s3control delete-access-point](https://docs.aws.amazon.com/cli/latest/reference/s3control/delete-access-point.html)
- [aws s3control create-access-point](https://docs.aws.amazon.com/cli/latest/reference/s3control/create-access-point.html)
- [aws s3control put-access-point-policy](https://docs.aws.amazon.com/cli/latest/reference/s3control/put-access-point-policy.html)
- [Managing access to shared datasets with access points](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points.html)
- [Creating an access point](https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-access-points.html)
- [Configuring IAM policies for using access points](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-policies.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Deploy a cross-account access point with 1) an unauthorized bucket or 2) an authorized bucket in an unauthorized AWS account; it should be detected.
