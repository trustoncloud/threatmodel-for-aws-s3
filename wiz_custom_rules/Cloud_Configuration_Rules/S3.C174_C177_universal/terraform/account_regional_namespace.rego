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

WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not unsupported_region(bucket)
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
    not unsupported_region(bucket)
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
