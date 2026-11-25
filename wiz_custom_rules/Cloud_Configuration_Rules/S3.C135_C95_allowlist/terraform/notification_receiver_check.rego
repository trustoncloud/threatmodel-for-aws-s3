package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
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
# --- toc-match begin: tf v1 ---
# A Terraform value that is still an unresolved reference ("${...}"). Treat
# it as unknown: never compare it with an allowlist as a string.
tocm_tf_unresolved(v) {
    is_string(v)
    contains(v, "${")
}
# --- toc-match end: tf v1 ---

# --- tf_never_created: begin ---
# A resource with a literal count of 0 or an empty for_each is never created
# and is not judged; any other expression is judged.
tf_expression(v) := trim_space(trim_suffix(trim_prefix(trim_space(v), "${"), "}")) {
    is_string(v)
}

tf_empty_collection := `^(\[\s*\]|\{\s*\}|toset\(\s*(\[\s*\]|\{\s*\})\s*\))$`

tf_zero(v) {
    v == 0
}

tf_zero(v) {
    tf_expression(v) == "0"
}

tf_empty(v) {
    is_array(v)
    count(v) == 0
}

tf_empty(v) {
    is_object(v)
    count(v) == 0
}

tf_empty(v) {
    regex.match(tf_empty_collection, tf_expression(v))
}

tf_not_created(r) {
    tf_zero(object.get(r, "count", null))
}

tf_not_created(r) {
    tf_empty(object.get(r, "for_each", null))
}
# --- tf_never_created: end ---

# --- tf_dynamic: begin ---
# A dynamic block generates blocks the source does not show; one whose
# for_each is a literal empty collection generates nothing. Needs
# tf_never_created.
tf_dynamic_blocks(b, label) := {d |
    d := terraLib.getArray(b.dynamic[_][label])[_]
    is_object(d)
} | {d |
    d := terraLib.getArray(b.dynamic[label])[_]
    is_object(d)
}

tf_dynamic(b, label) {
    d := tf_dynamic_blocks(b, label)[_]
    not tf_empty(object.get(d, "for_each", null))
}
# --- tf_dynamic: end ---

# A receiver given by reference is known only at apply and is not compared.
WizPolicy[result] {
    document := input.document[i]
    n := document.resource.aws_s3_bucket_notification[name]
    not tf_not_created(n)
    t := terraLib.getArray(n.topic)[idx]
    not tocm_tf_unresolved(t.topic_arn)
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
    not tf_not_created(n)
    q := terraLib.getArray(n.queue)[idx]
    not tocm_tf_unresolved(q.queue_arn)
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
    not tf_not_created(n)
    lf := terraLib.getArray(n.lambda_function)[idx]
    not tocm_tf_unresolved(lf.lambda_function_arn)
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

# Dynamic receiver blocks cannot be compared, so each is reported.
WizPolicy[result] {
    document := input.document[i]
    n := document.resource.aws_s3_bucket_notification[name]
    not tf_not_created(n)
    kind := {"topic", "queue", "lambda_function"}[_]
    tf_dynamic(n, kind)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_notification",
        "resourceName": terraLib.get_resource_name(n, name),
        "searchKey": sprintf("aws_s3_bucket_notification[%s].dynamic.%s", [name, kind]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("each %s receiver written out, so it can be compared with the authorized set: %v", [kind, authorized_notification_receivers]),
        "keyActualValue": sprintf("%s receivers are generated by a dynamic block, so they cannot be compared", [kind]),
        "resourceTags": terraLib.get_resource_tags(n),
    }
}

# --- EventBridge ---
# A bucket is a literal name, or an aws_s3_bucket reference with a literal
# name. Other buckets are left to the cloud matcher.
bucket_literal(v) {
    is_string(v)
    not tocm_tf_unresolved(v)
    not regex.match(`^(aws_s3_bucket|var|local|module|data)\.`, v)
}

notification_bucket(document, n) := n.bucket {
    bucket_literal(n.bucket)
}

notification_bucket(document, n) := b {
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket)\}?$`, n.bucket, 1)[0]
    b := document.resource.aws_s3_bucket[m[1]].bucket
    bucket_literal(b)
}

# eventbridge defaults to false; only an explicit true enables delivery.
eventbridge_on(n) { n.eventbridge == true }

eventbridge_on(n) {
    is_string(n.eventbridge)
    lower(n.eventbridge) == "true"
}

WizPolicy[result] {
    document := input.document[i]
    n := document.resource.aws_s3_bucket_notification[name]
    not tf_not_created(n)
    eventbridge_on(n)
    bucket := notification_bucket(document, n)
    count({bucket} & eventbridge_buckets) == 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_notification",
        "resourceName": terraLib.get_resource_name(n, name),
        "searchKey": sprintf("aws_s3_bucket_notification[%s].eventbridge", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("eventbridge may be true only for buckets in eventbridge_buckets: %v. Approving EventBridge delivery does not check where EventBridge rules forward the events", [eventbridge_buckets]),
        "keyActualValue": sprintf("eventbridge is true for bucket '%s', which is not in eventbridge_buckets", [bucket]),
        "resourceTags": terraLib.get_resource_tags(n),
    }
}
