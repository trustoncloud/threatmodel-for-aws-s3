package wiz

# 1. PASS: EventBridge is Enabled
test_notification_pass_eventbridge {
    result == "pass" with input as {
        "properties": {
            "bucketNotificationConfiguration": {
                "EventBridgeConfiguration": {} # Existence implies enabled
            }
        }
    }
}

# 2. PASS: Lambda is Enabled (List is not empty)
test_notification_pass_lambda {
    result == "pass" with input as {
        "properties": {
            "bucketNotificationConfiguration": {
                "LambdaFunctionConfigurations": [
                    { "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123:function:my-func" }
                ]
            }
        }
    }
}

# 3. PASS: SQS (Queue) is Enabled
test_notification_pass_queue {
    result == "pass" with input as {
        "properties": {
            "bucketNotificationConfiguration": {
                "QueueConfigurations": [
                    { "QueueArn": "arn:aws:sqs:us-east-1:123:my-queue" }
                ]
            }
        }
    }
}

# 4. PASS: SNS (Topic) is Enabled
test_notification_pass_topic {
    result == "pass" with input as {
        "properties": {
            "bucketNotificationConfiguration": {
                "TopicConfigurations": [
                    { "TopicArn": "arn:aws:sns:us-east-1:123:my-topic" }
                ]
            }
        }
    }
}

# 5. FAIL: Config object exists but is empty (All null)
test_notification_fail_empty_config {
    result == "fail" with input as {
        "properties": {
            "bucketNotificationConfiguration": {
                "LambdaFunctionConfigurations": [],
                "QueueConfigurations": [],
                "TopicConfigurations": []
                # EventBridge missing
            }
        }
    }
}

# 6. FAIL: Notification Configuration is entirely missing
test_notification_fail_missing_config {
    result == "fail" with input as {
        "properties": {}
    }
}

# 7. SKIP: Input is Null
test_notification_skip {
    result == "skip" with input as null
}