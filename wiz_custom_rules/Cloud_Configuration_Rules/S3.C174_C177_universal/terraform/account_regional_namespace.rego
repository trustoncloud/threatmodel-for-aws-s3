package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Regions where S3 offers no account regional namespace; buckets there are not
# judged. Keep in sync with the cloud matcher.
unsupported_regions := {"me-south-1", "me-central-1"}

# --- Logic ---
# Only the per-resource region argument is visible here, not the provider's.
unsupported_region(bucket) {
    unsupported_regions[bucket.region]
}

# A namespace set from a variable or an expression cannot be judged statically.
literal_namespace(v) {
    is_string(v)
    not contains(v, "${")
}

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

# A region given by reference is known only at apply and is not judged.
tf_scope_unresolved(bucket) {
    tocm_tf_unresolved(bucket.region)
}

WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    not unsupported_region(bucket)
    not tf_scope_unresolved(bucket)
    not terraLib.validKey(bucket, "bucket_namespace")

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "bucket_namespace must be \"account-regional\"",
        "keyActualValue": "bucket_namespace is not set, so the bucket is created in the global namespace",
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    not unsupported_region(bucket)
    not tf_scope_unresolved(bucket)
    ns := bucket.bucket_namespace
    literal_namespace(ns)
    lower(ns) != "account-regional"

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s].bucket_namespace", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "bucket_namespace must be \"account-regional\"",
        "keyActualValue": sprintf("bucket_namespace is \"%s\"", [ns]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
