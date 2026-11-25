# Remediation

A notification on the bucket in the finding sends events to an SNS topic, SQS queue or Lambda function that is not authorized, or to Amazon EventBridge from a bucket not listed in `eventbridge_buckets`. Remove that receiver, point it at an authorized one, or turn EventBridge delivery off. `put-bucket-notification-configuration` replaces the whole configuration, so put back the rest. Leave out `EventBridgeConfiguration` to turn EventBridge delivery off, or keep it as `{}` to keep it on:

```bash
aws s3api get-bucket-notification-configuration --bucket <bucket-name>
aws s3api put-bucket-notification-configuration --bucket <bucket-name> --notification-configuration '{"QueueConfigurations": [{"QueueArn": "<queue-arn>", "Events": ["s3:ObjectCreated:*"]}]}'
```

An empty configuration (`'{}'`) removes every notification, EventBridge delivery included. If the receiver is approved, add its ARN to `authorized_notification_receivers` instead, with any Lambda version or alias suffix the notification names, since ARNs are compared exactly. If the bucket may send events to EventBridge, add its name to `eventbridge_buckets`; that approval does not check where EventBridge rules forward the events. Replace `<bucket-name>` with the bucket in the finding and `<queue-arn>` with an authorized receiver.

## References

- [aws s3api get-bucket-notification-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-notification-configuration.html)
- [aws s3api put-bucket-notification-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-notification-configuration.html)
- [Event notification types and destinations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html)
- [Amazon S3 Event Notifications](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html)

Checked 2026-11-19 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create an unauthorized receiver; it should be detected.
