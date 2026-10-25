package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized replication routes: source bucket name, then each destination
# bucket ARN it may replicate to and that route's expected settings. This rule
# reads the source bucket names; S3.C88 checks the routes. Keep in sync with
# the cloud matcher and S3.C88.
authorized_replications := {
    "authorized-source-bucket": {
        "arn:aws:s3:::authorized-replica-bucket": {
            "replica_kms_key": "arn:aws:kms:us-west-2:123456789012:key/authorized-replica-key",
            "owner_override": false,
            "rtc": true,
        },
        "arn:aws:s3:::authorized-archive-bucket": {
            "replica_kms_key": null,
            "owner_override": false,
            "rtc": false,
        },
    },
}

# --- Source bucket ---
# The replication configuration names its bucket as a literal or as a reference
# (interpolated or bare) to an aws_s3_bucket whose `bucket` is a literal.
literal(v) {
    is_string(v)
    not contains(v, "${")
    not regex.match(`^(aws_s3_bucket|var|local|module|data)\.`, v)
}

source_name(document, rc) := rc.bucket {
    literal(rc.bucket)
}

source_name(document, rc) := n {
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket)\}?$`, rc.bucket, 1)[0]
    n := document.resource.aws_s3_bucket[m[1]].bucket
    literal(n)
}

tf_replication_enabled(rc) {
    lower(terraLib.getArray(rc.rule)[_].status) == "enabled"
}

# --- Logic ---
# A bucket whose name cannot be resolved statically is not judged.
WizPolicy[result] {
    document := input.document[i]
    rc := document.resource.aws_s3_bucket_replication_configuration[name]
    tf_replication_enabled(rc)
    source := source_name(document, rc)
    not authorized_replications[source]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_replication_configuration",
        "resourceName": terraLib.get_resource_name(rc, name),
        "searchKey": sprintf("aws_s3_bucket_replication_configuration[%s].bucket", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("only authorized buckets may have replication enabled: %v", [sort([b | authorized_replications[b]])]),
        "keyActualValue": sprintf("bucket '%s' has replication enabled but is not authorized to replicate", [source]),
        "resourceTags": terraLib.get_resource_tags(rc),
    }
}
