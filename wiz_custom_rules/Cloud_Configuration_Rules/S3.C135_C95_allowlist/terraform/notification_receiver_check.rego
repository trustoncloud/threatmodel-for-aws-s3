package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_notification_receivers := {
    "arn:aws:sns:us-east-1:123456789012:authorized-topic",
    "arn:aws:sqs:us-east-1:123456789012:authorized-queue",
    "arn:aws:lambda:us-east-1:123456789012:function:authorized-function",
}

# --- Logic ---
# One finding per unauthorized receiver, across the three receiver block types.
WizPolicy[result] {
    document := input.document[i]
    n := document.resource.aws_s3_bucket_notification[name]
    t := terraLib.getArray(n.topic)[idx]
    not authorized_notification_receivers[t.topic_arn]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_notification",
        "resourceName": terraLib.get_resource_name(n, name),
        "searchKey": sprintf("aws_s3_bucket_notification[%s].topic[%d].topic_arn", [name, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("topic_arn must be in the authorized set: %v", [authorized_notification_receivers]),
        "keyActualValue": sprintf("topic_arn is '%v' (not authorized)", [t.topic_arn]),
        "resourceTags": terraLib.get_resource_tags(n),
    }
}

WizPolicy[result] {
    document := input.document[i]
    n := document.resource.aws_s3_bucket_notification[name]
    q := terraLib.getArray(n.queue)[idx]
    not authorized_notification_receivers[q.queue_arn]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_notification",
        "resourceName": terraLib.get_resource_name(n, name),
        "searchKey": sprintf("aws_s3_bucket_notification[%s].queue[%d].queue_arn", [name, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("queue_arn must be in the authorized set: %v", [authorized_notification_receivers]),
        "keyActualValue": sprintf("queue_arn is '%v' (not authorized)", [q.queue_arn]),
        "resourceTags": terraLib.get_resource_tags(n),
    }
}

WizPolicy[result] {
    document := input.document[i]
    n := document.resource.aws_s3_bucket_notification[name]
    lf := terraLib.getArray(n.lambda_function)[idx]
    not authorized_notification_receivers[lf.lambda_function_arn]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_notification",
        "resourceName": terraLib.get_resource_name(n, name),
        "searchKey": sprintf("aws_s3_bucket_notification[%s].lambda_function[%d].lambda_function_arn", [name, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("lambda_function_arn must be in the authorized set: %v", [authorized_notification_receivers]),
        "keyActualValue": sprintf("lambda_function_arn is '%v' (not authorized)", [lf.lambda_function_arn]),
        "resourceTags": terraLib.get_resource_tags(n),
    }
}
