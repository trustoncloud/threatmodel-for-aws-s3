Attach an `aws_s3_bucket_policy` to the bucket with this Deny, and add no other condition to it. List only keys in `authorized_kms_key_ids`, or add a key ARN there once approved. The deprecated `policy` argument of `aws_s3_bucket` is read too. Only one bucket policy applies after apply, so a bucket that sets more than one (the argument and an `aws_s3_bucket_policy`, or several of them) is reported unless each holds the Deny.

```hcl
resource "aws_s3_bucket" "example" {
  bucket = "<bucket-name>"
}

resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "${aws_s3_bucket.example.arn}/*",
     "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:<region>:<account-id>:key/<key-id>"}}}
  ]
}
POLICY
}
```

The policy can also be built with an `aws_iam_policy_document` data source.

## References

- [aws_s3_bucket (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket)
- [aws_s3_bucket_policy (hashicorp/aws 6.70.0)](https://registry.terraform.io/providers/hashicorp/aws/6.70.0/docs/resources/s3_bucket_policy)

Checked 2026-11-19 against hashicorp/aws 5.100.0 and 6.70.0: resources, arguments and links.
