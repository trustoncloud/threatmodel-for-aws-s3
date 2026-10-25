# S3.C95 (notification_receiver_check) - allowlist - COMPLIANT (0 findings)

resource "aws_s3_bucket_notification" "authorized_receivers" {
  bucket = "notify-bucket"

  topic {
    topic_arn = "arn:aws:sns:us-east-1:123456789012:authorized-topic"
    events    = ["s3:ObjectCreated:*"]
  }

  queue {
    queue_arn = "arn:aws:sqs:us-east-1:123456789012:authorized-queue"
    events    = ["s3:ObjectRemoved:*"]
  }
}
