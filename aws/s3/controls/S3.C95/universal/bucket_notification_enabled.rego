package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Find the Notification Config (Handles Root vs. Properties nesting)
notification_config := config {
    input.bucketNotificationConfiguration != null
    config := input.bucketNotificationConfiguration
} else := config {
    input.properties.bucketNotificationConfiguration != null
    config := input.properties.bucketNotificationConfiguration
}

# Helper: Check if ANY notification type is enabled
# We use 'not is_null' or direct existence checks to be safe.
is_notification_enabled {
    notification_config.EventBridgeConfiguration != null
}
is_notification_enabled {
    notification_config.LambdaFunctionConfigurations != null
    count(notification_config.LambdaFunctionConfigurations) > 0
}
is_notification_enabled {
    notification_config.QueueConfigurations != null
    count(notification_config.QueueConfigurations) > 0
}
is_notification_enabled {
    notification_config.TopicConfigurations != null
    count(notification_config.TopicConfigurations) > 0
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if we can't find the config object at all
    not notification_config
} else := "fail" {
    # Fail if config exists but no specific notification is enabled
    not is_notification_enabled
}

# --- Metadata ---
currentConfiguration := "S3 Bucket Event Notifications are disabled." {
    result == "fail"
} else := "S3 Bucket Event Notifications are enabled."

expectedConfiguration := "S3 Bucket must have at least one Event Notification configured (EventBridge, Lambda, SQS, or SNS)."