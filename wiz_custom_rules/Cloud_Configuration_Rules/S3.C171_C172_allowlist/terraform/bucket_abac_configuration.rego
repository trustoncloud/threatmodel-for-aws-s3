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
# The bucket is a literal or a reference to an aws_s3_bucket with a literal name.
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

# --- Logic ---
# A bucket whose name cannot be resolved statically is not judged. ABAC is off
# by default, so an authorized bucket needs an aws_s3_bucket_abac in its file.

# ABAC enabled on a bucket that is not authorized for it.
WizPolicy[result] {
    document := input.document[i]
    abac := document.resource.aws_s3_bucket_abac[name]
    not tf_not_created(abac)
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
    not tf_not_created(abac)
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
    not tf_not_created(bucket)
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

# An aws_s3_bucket_abac that is never created leaves ABAC off.
abac_declared(document, bucket_name) {
    abac := document.resource.aws_s3_bucket_abac[_]
    not tf_not_created(abac)
    abac_bucket_name(document, abac) == bucket_name
}

tf_abac_bucket_text(document, abac) := sprintf("bucket '%s'", [b]) {
    b := abac_bucket_name(document, abac)
} else := "a bucket whose name is not resolved by this source scan"

# A dynamic abac_status cannot be judged and is reported for any bucket.
WizPolicy[result] {
    document := input.document[i]
    abac := document.resource.aws_s3_bucket_abac[name]
    not tf_not_created(abac)
    tf_dynamic(abac, "abac_status")

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_abac",
        "resourceName": terraLib.get_resource_name(abac, name),
        "searchKey": sprintf("aws_s3_bucket_abac[%s].dynamic.abac_status", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("abac_status written out, so it can be checked: ABAC enabled only on authorized buckets: %v", [sort([b | authorized_abac_buckets[b]])]),
        "keyActualValue": sprintf("the abac_status of %s is generated by a dynamic block, which cannot be judged", [tf_abac_bucket_text(document, abac)]),
        "resourceTags": terraLib.get_resource_tags(abac),
    }
}
