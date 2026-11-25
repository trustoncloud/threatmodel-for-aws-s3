package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Buckets that require SSE-C and must not block it: "bucket" or "bucket/prefix/"
# (a path keeps SSE-C allowed bucket-wide). Every other bucket must block SSE-C.
# Keep in sync with the cloud matcher and S3.C147.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
}

# --- Default encryption setting ---
# Only an explicit blocked_encryption_types counts: without it, the outcome
# depends on the bucket's age and the account's SSE-C history.
blocked_types(document, bucket, name) := {t |
    cfg := document.resource.aws_s3_bucket_server_side_encryption_configuration[cName]
    not tf_not_created(cfg)
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

# A rule that a dynamic block generates hides blocked_encryption_types.
tf_blocked_types_generated(document, bucket, name) {
    cfg := document.resource.aws_s3_bucket_server_side_encryption_configuration[cName]
    not tf_not_created(cfg)
    terraLib.associatedResources(cfg, bucket, cName, name, "bucket", "id")
    tf_dynamic(cfg, "rule")
}

# An entry (or whole list) given by reference is known only at apply; not judged.
tf_blocked_types_unresolved(document, bucket, name) {
    tocm_tf_unresolved(blocked_types(document, bucket, name)[_])
}

# A bucket named by reference may require SSE-C, so allowing it is not judged.
# With no explicit setting it fails in either group.
tf_unresolved_name_allows_ssec(bname, types) {
    tocm_tf_unresolved(bname)
    types["NONE"]
}

tf_block_expected(bname) := msg {
    tocm_tf_unresolved(bname)
    msg := sprintf("bucket '%s' is named by reference and must set blocked_encryption_types explicitly in aws_s3_bucket_server_side_encryption_configuration: [\"NONE\"] if it requires SSE-C, [\"SSE-C\"] otherwise", [bname])
} else := sprintf("bucket '%s' must set blocked_encryption_types = [\"SSE-C\"] in aws_s3_bucket_server_side_encryption_configuration", [bname])

# A bucket that requires SSE-C must explicitly allow it.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    bname := bucket_name(bucket, name)
    tf_ssec_required(bname)
    not tf_blocked_types_unresolved(document, bucket, name)
    not tf_blocked_types_generated(document, bucket, name)
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
    not tf_not_created(bucket)
    bname := bucket_name(bucket, name)
    not tf_ssec_required(bname)
    not tf_blocked_types_unresolved(document, bucket, name)
    not tf_blocked_types_generated(document, bucket, name)
    types := blocked_types(document, bucket, name)
    not types["SSE-C"]
    not tf_unresolved_name_allows_ssec(bname, types)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": tf_block_expected(bname),
        "keyActualValue": sprintf("bucket '%s' does not explicitly block SSE-C: blocked_encryption_types %s", [bname, types_label(types)]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# A dynamic block generates the setting, in either group.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    bname := bucket_name(bucket, name)
    tf_blocked_types_generated(document, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "blocked_encryption_types written out in a rule block of aws_s3_bucket_server_side_encryption_configuration, so it can be read: [\"NONE\"] for a bucket in buckets_requiring_ssec, [\"SSE-C\"] for any other",
        "keyActualValue": sprintf("bucket '%s' has its blocked encryption types in a rule generated by a dynamic block, so they cannot be read", [bname]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
