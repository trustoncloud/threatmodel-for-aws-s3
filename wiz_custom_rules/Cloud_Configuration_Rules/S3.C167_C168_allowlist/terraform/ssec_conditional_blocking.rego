package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Buckets that require SSE-C and therefore must NOT block it: a bucket name for
# the whole bucket, or "bucket/prefix/" for one path inside it. The block
# setting covers the whole bucket, so a path entry keeps SSE-C allowed on its
# bucket. Every other bucket must block SSE-C. Keep in sync with the cloud
# matcher and S3.C147.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
}

# --- Default encryption setting ---
# blocked_encryption_types on aws_s3_bucket_server_side_encryption_configuration.
# Without it the outcome depends on the bucket's age and the account's SSE-C
# history, so only an explicit value counts.
blocked_types(document, bucket, name) := {t |
    cfg := document.resource.aws_s3_bucket_server_side_encryption_configuration[cName]
    terraLib.associatedResources(cfg, bucket, cName, name, "bucket", "id")
    rule := terraLib.getArray(cfg.rule)[_]
    t := terraLib.getArray(rule.blocked_encryption_types)[_]
}

# The bucket name is the `bucket` argument, falling back to the local name.
bucket_name(bucket, name) := object.get(bucket, "bucket", name)

tf_ssec_required(bname) {
    buckets_requiring_ssec[bname]
}

tf_ssec_required(bname) {
    startswith(buckets_requiring_ssec[_], concat("", [bname, "/"]))
}

types_label(types) := "is not set" { count(types) == 0 } else := sprintf("is %v", [sort([t | t := types[_]])])

# --- Logic ---
# A bucket that requires SSE-C must explicitly allow it.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    bname := bucket_name(bucket, name)
    tf_ssec_required(bname)
    types := blocked_types(document, bucket, name)
    not types["NONE"]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' requires SSE-C and must set blocked_encryption_types = [\"NONE\"] in aws_s3_bucket_server_side_encryption_configuration", [bname]),
        "keyActualValue": sprintf("bucket '%s' does not explicitly allow SSE-C: blocked_encryption_types %s", [bname, types_label(types)]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Every other bucket must explicitly block SSE-C.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    bname := bucket_name(bucket, name)
    not tf_ssec_required(bname)
    types := blocked_types(document, bucket, name)
    not types["SSE-C"]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must set blocked_encryption_types = [\"SSE-C\"] in aws_s3_bucket_server_side_encryption_configuration", [bname]),
        "keyActualValue": sprintf("bucket '%s' does not explicitly block SSE-C: blocked_encryption_types %s", [bname, types_label(types)]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
