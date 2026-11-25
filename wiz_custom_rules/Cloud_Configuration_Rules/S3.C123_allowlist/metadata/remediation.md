# Remediation

The S3 Batch Operations job in the finding runs as an IAM role that is not approved. No command changes a job's role, so cancel the job if it has not ended and create a new one that runs as an approved role (`aws s3control create-job --role-arn <role-arn>`, with the job's other settings):

```bash
aws s3control describe-job --region <region> --account-id <account-id> --job-id <job-id> --query "Job.[Status,RoleArn]"
aws s3control update-job-status --region <region> --account-id <account-id> --job-id <job-id> --requested-job-status Cancelled --status-update-reason "Role not approved"
```

An ended job (`Complete`, `Failed` or `Cancelled`) keeps its finding while S3 lists it; review what it did with that role. If the role is approved, add its ARN to `authorized_batch_job_roles` instead. Replace `<region>`, `<account-id>` and `<job-id>` with the values in the finding's job ARN (`arn:aws:s3:<region>:<account-id>:job/<job-id>`), and `<role-arn>` with an approved role.

## References

- [aws s3control describe-job](https://docs.aws.amazon.com/cli/latest/reference/s3control/describe-job.html)
- [aws s3control update-job-status](https://docs.aws.amazon.com/cli/latest/reference/s3control/update-job-status.html)
- [aws s3control create-job](https://docs.aws.amazon.com/cli/latest/reference/s3control/create-job.html)
- [Tracking job status and completion reports](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-job-status.html)
- [Granting permissions for Batch Operations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-iam-role-policies.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create/modify a Batch job with an unauthorized IAM role; it should be detected.
