package wiz

# --- Configuration ---
# Authorized notification receiver ARNs (SNS topics, SQS queues, Lambda functions).
authorized_notification_receivers := {
    "arn:aws:sns:us-east-1:123456789012:authorized-topic",
    "arn:aws:sqs:us-east-1:123456789012:authorized-queue",
    "arn:aws:lambda:us-east-1:123456789012:function:authorized-function",
}

# --- Logic ---
default result := "pass"

notification_config := input.bucketNotificationConfiguration

fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketNotificationConfiguration.result == "Success"
}

receivers[arn] {
    arn := notification_config.TopicConfigurations[_].TopicArn
}

receivers[arn] {
    arn := notification_config.QueueConfigurations[_].QueueArn
}

receivers[arn] {
    arn := notification_config.LambdaFunctionConfigurations[_].LambdaFunctionArn
}

unauthorized_receivers[arn] {
    arn := receivers[_]
    not authorized_notification_receivers[arn]
}

result := "skip" {
    not fetch_ok
} else := "skip" {
    notification_config == null
} else := "fail" {
    count(unauthorized_receivers) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket notifications target unauthorized receiver(s): %v", [unauthorized_receivers]) {
    result == "fail"
} else := "Bucket notification receivers are authorized, or no notifications are configured."

expectedConfiguration := sprintf("Every notification receiver ARN must be in the authorized set: %v", [authorized_notification_receivers])
