package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Buckets authorized to use ABAC (tag-based access control), by bucket name.
# ABAC must be enabled on each of these and on no other bucket. An empty set
# means no bucket may enable ABAC.
authorized_abac_buckets := {
    "authorized-abac-bucket",
    "authorized-abac-reports",
}

# --- Bucket names ---
# aws_s3_bucket_abac names its bucket as a literal or as a reference
# (interpolated or bare) to an aws_s3_bucket whose `bucket` is a literal.
literal(v) {
    is_string(v)
    not contains(v, "${")
    not regex.match(`^(aws_s3_bucket|var|local|module|data)\.`, v)
}

abac_bucket_name(document, abac) := abac.bucket {
    literal(abac.bucket)
}

abac_bucket_name(document, abac) := n {
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket)\}?$`, abac.bucket, 1)[0]
    n := document.resource.aws_s3_bucket[m[1]].bucket
    literal(n)
}

abac_status(abac) := lower(terraLib.getArray(abac.abac_status)[_].status)

# --- Logic ---
# A bucket whose name cannot be resolved statically is not judged. ABAC is off
# by default, so an authorized bucket needs an aws_s3_bucket_abac in the same
# file, which is the unit a Terraform scan reads.

# ABAC enabled on a bucket that is not authorized for it.
WizPolicy[result] {
    document := input.document[i]
    abac := document.resource.aws_s3_bucket_abac[name]
    abac_status(abac) == "enabled"
    bucket := abac_bucket_name(document, abac)
    not authorized_abac_buckets[bucket]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_abac",
        "resourceName": terraLib.get_resource_name(abac, name),
        "searchKey": sprintf("aws_s3_bucket_abac[%s].abac_status.status", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("ABAC enabled only on authorized buckets: %v", [sort([b | authorized_abac_buckets[b]])]),
        "keyActualValue": sprintf("ABAC is enabled on bucket '%s', which is not authorized for it", [bucket]),
        "resourceTags": terraLib.get_resource_tags(abac),
    }
}

# ABAC disabled on an authorized bucket.
WizPolicy[result] {
    document := input.document[i]
    abac := document.resource.aws_s3_bucket_abac[name]
    abac_status(abac) == "disabled"
    bucket := abac_bucket_name(document, abac)
    authorized_abac_buckets[bucket]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_abac",
        "resourceName": terraLib.get_resource_name(abac, name),
        "searchKey": sprintf("aws_s3_bucket_abac[%s].abac_status.status", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("ABAC enabled on authorized bucket '%s'", [bucket]),
        "keyActualValue": sprintf("ABAC is disabled on authorized bucket '%s'", [bucket]),
        "resourceTags": terraLib.get_resource_tags(abac),
    }
}

# An authorized bucket with no aws_s3_bucket_abac, so ABAC stays off.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    literal(bucket.bucket)
    authorized_abac_buckets[bucket.bucket]
    not abac_declared(document, bucket.bucket)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("an aws_s3_bucket_abac enabling ABAC on authorized bucket '%s'", [bucket.bucket]),
        "keyActualValue": "no aws_s3_bucket_abac is declared for this bucket, so ABAC is off",
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

abac_declared(document, bucket_name) {
    abac_bucket_name(document, document.resource.aws_s3_bucket_abac[_]) == bucket_name
}
