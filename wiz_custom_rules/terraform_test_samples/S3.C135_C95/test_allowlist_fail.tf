# S3.C95 (notification_receiver_check) - allowlist - VIOLATING

# Unauthorized topic, queue, and lambda receivers: 3 findings
resource "aws_s3_bucket_notification" "rogue_receivers" {
  bucket = "notify-bucket"

  topic {
    topic_arn = "arn:aws:sns:us-east-1:999999999999:rogue-topic"
    events    = ["s3:ObjectCreated:*"]
  }

  queue {
    queue_arn = "arn:aws:sqs:us-east-1:999999999999:rogue-queue"
    events    = ["s3:ObjectRemoved:*"]
  }

  lambda_function {
    lambda_function_arn = "arn:aws:lambda:us-east-1:999999999999:function:rogue-function"
    events              = ["s3:ObjectCreated:Put"]
  }
}
