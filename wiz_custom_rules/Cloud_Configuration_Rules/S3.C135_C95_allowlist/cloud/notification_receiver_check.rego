package wiz

# --- Configuration ---
# Authorized notification receiver ARNs (SNS topics, SQS queues, Lambda functions).
authorized_notification_receivers := {
    "arn:aws:sns:us-east-1:123456789012:authorized-topic",
    "arn:aws:sqs:us-east-1:123456789012:authorized-queue",
    "arn:aws:lambda:us-east-1:123456789012:function:authorized-function",
}

# Bucket names (exact) allowed to send events to EventBridge in their own
# account. Listing one does not check where EventBridge rules forward events.
eventbridge_buckets := {
    "authorized-eventbridge-bucket",
    "authorized-events-archive-bucket",
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

# EventBridge delivery is an empty object when enabled and null when off.
eventbridge_enabled {
    eb := notification_config.EventBridgeConfiguration
    eb != null
}

bucket_name := object.get(input, "Name", "")

eventbridge_unapproved {
    eventbridge_enabled
    count({bucket_name} & eventbridge_buckets) == 0
}

findings[msg] {
    count(unauthorized_receivers) > 0
    msg := sprintf("unauthorized receiver(s) %v", [sort([a | a := unauthorized_receivers[_]])])
}

findings[msg] {
    eventbridge_unapproved
    msg := sprintf("EventBridge delivery is enabled on bucket '%s', which is not in eventbridge_buckets", [bucket_name])
}

result := "skip" {
    not fetch_ok
} else := "skip" {
    notification_config == null
} else := "fail" {
    count(findings) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket notifications: %s.", [concat("; ", sort([m | m := findings[_]]))]) {
    result == "fail"
} else := "Bucket notification receivers are authorized and EventBridge delivery is off or approved, or no notifications are configured."

expectedConfiguration := sprintf("Every notification receiver ARN must be in the authorized set %v, and only buckets in eventbridge_buckets %v may send events to EventBridge. Approving EventBridge delivery does not check where EventBridge rules forward the events.", [authorized_notification_receivers, eventbridge_buckets])
