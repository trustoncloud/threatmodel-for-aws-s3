# Remediation

The policy of the bucket in the finding grants CloudFront access through an unapproved origin access identity, or to the `cloudfront.amazonaws.com` service without an `aws:SourceArn` test limited to approved distributions. Remove the statement, or limit it to an approved distribution:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontOacReadOnly",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::<bucket-name>/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::<account-id>:distribution/<distribution-id>"
        }
      }
    }
  ]
}
```

`put-bucket-policy` replaces the whole policy, so remove or correct each CloudFront statement in the current one, saved as `policy.json`:

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://policy.json
```

Write each distribution ARN in full, with no wildcard, under `StringEquals`, `ArnEquals` or `ArnLike`. If the distribution or origin access identity is approved, add its ID to `authorized_cloudfront_ids` instead. CloudFront access through an access point or Object Lambda Access Point is not checked. Replace `<bucket-name>` with the bucket in the finding, and `<account-id>` and `<distribution-id>` with the approved distribution.

## References

- [aws s3api get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [aws s3api put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [Restrict access to an Amazon S3 origin](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html)
- [Bucket policies for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create a non-authorized distribution or association; it should be detected.
