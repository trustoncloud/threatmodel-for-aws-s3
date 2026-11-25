package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Key ARNs any bucket may use for default encryption. Keep in sync with the
# cloud matcher and S3.C67.
authorized_kms_key_ids := {
    "arn:aws:kms:us-east-1:123456789012:key/authorized-key",
}

# Bucket name to the only key ARNs its default encryption may use. Other
# buckets use authorized_kms_key_ids. Names match exactly. Keep in sync with
# the cloud matcher.
authorized_kms_key_ids_by_bucket := {
    "finance-data-bucket": {"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
}

# Buckets that may keep SSE-S3 because their writers cannot use KMS, such as
# a server access log destination. Names match exactly. Keep in sync with the
# cloud matcher.
sse_s3_buckets := {
    "example-access-logs-bucket",
}

# --- Logic ---
# Default encryption comes from the standalone configuration or the inline
# block; an object Terraform uploads may set its own.

# SSE-KMS and DSSE-KMS encrypt with a KMS key; AES256 is SSE-S3.
tf_kms_algorithms := {"aws:kms", "aws:kms:dsse"}

tf_object_types := {"aws_s3_object", "aws_s3_object_copy", "aws_s3_bucket_object"}

# A value written in the source, known before apply.
tf_known(v) {
    is_string(v)
    trim_space(v) != ""
    not tocm_tf_unresolved(v)
}

tf_set(v) {
    is_string(v)
    trim_space(v) != ""
}

# --- Bucket names ---
# A bucket is named by a literal or a reference to a literal aws_s3_bucket;
# any other value is known only at apply.
tf_literal_name(v) {
    tf_known(v)
    not regex.match(`^(aws_s3_bucket|var|local|module|data)\.`, v)
    not tocm_arn_parts(v)
}

tf_bucket_ref(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.(?:id|bucket)\}?$`, v, 1)[0]
}

# The names a bucket argument can stand for, one per definition found; "" is
# a name known only at apply.
tf_bucket_names(i, v) := {v} {
    tf_literal_name(v)
} else := names {
    candidates := tf_lookup(i, "resource", "aws_s3_bucket", tf_bucket_ref(v))
    count(candidates) > 0
    names := {tf_own_name(c.block) | c := candidates[_]}
} else := {""}

# The name a bucket gives itself, or "" when it is known only at apply.
tf_own_name(b) := n {
    n := object.get(b, "bucket", null)
    tf_literal_name(n)
} else := ""

tf_bucket_label(bname) := sprintf("bucket '%s'", [bname]) {
    bname != ""
} else := "a bucket named only at apply"

# --- Authorized keys ---
tf_sse_s3_approved(bname) {
    sse_s3_buckets[bname]
}

tf_sse_s3_allowed(alg, bname) {
    alg == "AES256"
    tf_sse_s3_approved(bname)
}

tf_bucket_keys(bname) := keys {
    keys := authorized_kms_key_ids_by_bucket[bname]
} else := authorized_kms_key_ids

tf_any_listed_key := authorized_kms_key_ids | {k | k := authorized_kms_key_ids_by_bucket[_][_]}

# When the bucket is named only at apply, any listed key passes here.
tf_key_allowed(key, bname) {
    bname != ""
    tocm_arn_allowed(key, tf_bucket_keys(bname))
}

tf_key_allowed(key, bname) {
    bname == ""
    tocm_arn_allowed(key, tf_any_listed_key)
}

# A bare key ID needs the account and Region, so the cloud check reads it.
tf_key_id(v) {
    regex.match(`^(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`, trim_space(v))
}

tf_expected_keys(bname) := sort(tf_bucket_keys(bname)) {
    bname != ""
} else := sort(tf_any_listed_key)

# A bare alias resolves in the uploader's account, so it can name any key.
tf_key_problem(key, bname, subject) := msg {
    tf_known(key)
    startswith(trim_space(key), "alias/")
    msg := sprintf("%s names the key alias '%s', which resolves in the uploader's account", [subject, key])
} else := msg {
    tf_known(key)
    not startswith(trim_space(key), "alias/")
    not tf_key_id(key)
    not tf_key_allowed(key, bname)
    msg := sprintf("%s uses the KMS key '%s', which %s", [subject, key, tf_not_listed(bname)])
}

tf_not_listed(bname) := "is not authorized for that bucket" {
    bname != ""
} else := "is listed for no bucket"

# Undefined when the setting passes or is known only at apply.
tf_default_problem(d, bname) := msg {
    alg := object.get(d, "sse_algorithm", null)
    tf_known(alg)
    not tf_kms_algorithms[alg]
    not tf_sse_s3_allowed(alg, bname)
    msg := sprintf("the default encryption of %s is %s, not a KMS key", [tf_bucket_label(bname), alg])
} else := msg {
    alg := object.get(d, "sse_algorithm", null)
    tf_kms_algorithms[alg]
    not tf_set(object.get(d, "kms_master_key_id", null))
    msg := sprintf("the default encryption of %s is %s with no kms_master_key_id, so S3 uses the AWS managed key aws/s3", [tf_bucket_label(bname), alg])
} else := msg {
    alg := object.get(d, "sse_algorithm", null)
    tf_kms_algorithms[alg]
    msg := tf_key_problem(object.get(d, "kms_master_key_id", null), bname, sprintf("the default encryption of %s", [tf_bucket_label(bname)]))
}

# --- toc-match begin: arn v1 ---
# Parts of an AWS ARN; the resource keeps any further ":" characters.
tocm_arn_parts(arn) := {"partition": s[1], "service": s[2], "region": s[3], "account": s[4], "resource": r} {
    is_string(arn)
    s := split(trim_space(arn), ":")
    count(s) >= 6
    s[0] == "arn"
    s[1] != ""
    s[2] != ""
    r := concat(":", array.slice(s, 5, count(s)))
    r != ""
}

tocm_arn_equal(a, b) {
    tocm_arn_parts(a) == tocm_arn_parts(b)
}

tocm_arn_allowed(arn, allowed) {
    tocm_arn_equal(arn, allowed[_])
}

# Bucket name of an S3 bucket or object ARN (arn:aws:s3:::bucket[/key]).
tocm_s3_arn_bucket(arn) := b {
    p := tocm_arn_parts(arn)
    p.service == "s3"
    p.region == ""
    p.account == ""
    b := split(p.resource, "/")[0]
    b != ""
}
# --- toc-match end: arn v1 ---

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

# --- tf_scan_lookup: begin ---
# A reference reads the definition in its own file, else every definition in
# the other files of its module: the document id up to its last "/" or "\".
tf_module(i) := m[1] {
    m := regex.find_all_string_submatch_n(`^(.*)[/\\][^/\\]*$`, input.document[i].id, 1)[0]
} else := ""

# Documents whose <kind>.<rtype>.<name> a reference in document i reads.
tf_lookup_docs(i, kind, rtype, name) := {i} {
    input.document[i][kind][rtype][name]
} else := {j |
    input.document[j][kind][rtype][name]
    j != i
    tf_module(j) == tf_module(i)
}

# Those definitions, as {"doc": index, "block": definition}.
tf_lookup(i, kind, rtype, name) := {{"doc": j, "block": input.document[j][kind][rtype][name]} |
    j := tf_lookup_docs(i, kind, rtype, name)[_]
}

# A value naming <rtype>.<name> by its address, with any instance index.
tf_names_address(v, rtype, name) {
    is_string(v)
    regex.match(sprintf(`(^|[^A-Za-z0-9_.-])%s\.%s(\[[^\]]*\])?\.`, [rtype, name]), v)
}

# A reference v in document j reaches <rtype>.<name> of document i.
tf_reference_reaches(i, j, v, rtype, name) {
    j == i
}

tf_reference_reaches(i, j, v, rtype, name) {
    j != i
    tf_names_address(v, rtype, name)
    tf_lookup_docs(j, "resource", rtype, name)[i]
}
# --- tf_scan_lookup: end ---

# --- Default encryption settings ---
# Each rule of a created configuration, standalone or inline.
tf_sse_rules[entry] {
    document := input.document[i]
    cfg := document.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    not tf_not_created(cfg)
    bname := tf_bucket_names(i, object.get(cfg, "bucket", null))[_]
    rule := terraLib.getArray(object.get(cfg, "rule", []))[_]
    is_object(rule)
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "name": name,
        "resource": cfg,
        "bucket": bname,
        "rule": rule,
        "key": sprintf("aws_s3_bucket_server_side_encryption_configuration[%s].rule", [name]),
    }
}

tf_sse_rules[entry] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    block := terraLib.getArray(object.get(b, "server_side_encryption_configuration", []))[_]
    is_object(block)
    rule := terraLib.getArray(object.get(block, "rule", []))[_]
    is_object(rule)
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket",
        "name": name,
        "resource": b,
        "bucket": tf_own_name(b),
        "rule": rule,
        "key": sprintf("aws_s3_bucket[%s].server_side_encryption_configuration.rule", [name]),
    }
}

# --- A bucket's own configuration ---
# A standalone configuration names the bucket by a reference in its module,
# or by the literal name, which matches across modules.
tf_bucket_has_sse(i, b, name) {
    object.get(b, "server_side_encryption_configuration", null) != null
}

tf_bucket_has_sse(i, b, name) {
    tf_dynamic(b, "server_side_encryption_configuration")
}

tf_bucket_has_sse(i, b, name) {
    cfg := input.document[j].resource.aws_s3_bucket_server_side_encryption_configuration[_]
    not tf_not_created(cfg)
    ref := tf_bucket_ref(object.get(cfg, "bucket", null))
    ref == name
    tf_lookup_docs(j, "resource", "aws_s3_bucket", ref)[i]
}

tf_bucket_has_sse(i, b, name) {
    cfg := input.document[_].resource.aws_s3_bucket_server_side_encryption_configuration[_]
    not tf_not_created(cfg)
    tf_literal_name(b.bucket)
    cfg.bucket == b.bucket
}

# A bucket with no default encryption configuration gets SSE-S3.
WizPolicy[result] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    not tf_bucket_has_sse(i, b, name)
    bname := tf_own_name(b)
    not tf_sse_s3_approved(bname)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(b, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("an aws_s3_bucket_server_side_encryption_configuration with sse_algorithm aws:kms or aws:kms:dsse and an authorized kms_master_key_id: %v", [tf_expected_keys(bname)]),
        "keyActualValue": sprintf("%s has no default encryption configuration, so new objects are encrypted with SSE-S3 (the S3 default)", [tf_bucket_label(bname)]),
        "resourceTags": terraLib.get_resource_tags(b),
    }
}

# A rule that sets no default encryption leaves SSE-S3.
WizPolicy[result] {
    entry := tf_sse_rules[_]
    not tf_dynamic(entry.rule, "apply_server_side_encryption_by_default")
    object.get(entry.rule, "apply_server_side_encryption_by_default", null) == null
    not tf_sse_s3_approved(entry.bucket)

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": entry.key,
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("apply_server_side_encryption_by_default with sse_algorithm aws:kms or aws:kms:dsse and an authorized kms_master_key_id: %v", [tf_expected_keys(entry.bucket)]),
        "keyActualValue": sprintf("the default encryption rule of %s sets no apply_server_side_encryption_by_default, so new objects are encrypted with SSE-S3 (the S3 default)", [tf_bucket_label(entry.bucket)]),
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}

# A default encryption setting that does not use an authorized KMS key.
WizPolicy[result] {
    entry := tf_sse_rules[_]
    d := terraLib.getArray(object.get(entry.rule, "apply_server_side_encryption_by_default", []))[_]
    is_object(d)
    msg := tf_default_problem(d, entry.bucket)

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": sprintf("%s.apply_server_side_encryption_by_default", [entry.key]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("sse_algorithm aws:kms or aws:kms:dsse with a kms_master_key_id authorized for the bucket: %v", [tf_expected_keys(entry.bucket)]),
        "keyActualValue": msg,
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}

# --- Default encryption generated by a dynamic block ---
# A dynamic block hides the default encryption, so it is reported.
tf_dynamic_sources[entry] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    tf_dynamic(b, "server_side_encryption_configuration")
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket",
        "name": name,
        "resource": b,
        "bucket": tf_own_name(b),
        "key": sprintf("aws_s3_bucket[%s].dynamic.server_side_encryption_configuration", [name]),
    }
}

tf_dynamic_sources[entry] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    block := terraLib.getArray(object.get(b, "server_side_encryption_configuration", []))[_]
    is_object(block)
    tf_dynamic(block, "rule")
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket",
        "name": name,
        "resource": b,
        "bucket": tf_own_name(b),
        "key": sprintf("aws_s3_bucket[%s].server_side_encryption_configuration.dynamic.rule", [name]),
    }
}

tf_dynamic_sources[entry] {
    document := input.document[i]
    cfg := document.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    not tf_not_created(cfg)
    tf_dynamic(cfg, "rule")
    bname := tf_bucket_names(i, object.get(cfg, "bucket", null))[_]
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "name": name,
        "resource": cfg,
        "bucket": bname,
        "key": sprintf("aws_s3_bucket_server_side_encryption_configuration[%s].dynamic.rule", [name]),
    }
}

tf_dynamic_sources[entry] {
    r := tf_sse_rules[_]
    tf_dynamic(r.rule, "apply_server_side_encryption_by_default")
    entry := {
        "document": r.document,
        "type": r.type,
        "name": r.name,
        "resource": r.resource,
        "bucket": r.bucket,
        "key": sprintf("%s.dynamic.apply_server_side_encryption_by_default", [r.key]),
    }
}

WizPolicy[result] {
    entry := tf_dynamic_sources[_]

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": entry.key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("default encryption written out, with sse_algorithm aws:kms or aws:kms:dsse and a kms_master_key_id authorized for the bucket: %v", [tf_expected_keys(entry.bucket)]),
        "keyActualValue": sprintf("the default encryption of %s is generated by a dynamic block, so its key cannot be read", [tf_bucket_label(entry.bucket)]),
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}

# --- Objects uploaded by Terraform ---
# Any customer_* argument makes a copy use SSE-C; source_customer_* only reads
# the source object.
tf_ssec(obj) {
    tf_set(object.get(obj, ["customer_algorithm", "customer_key", "customer_key_md5"][_], null))
}

tf_object_problem(obj, bname) := msg {
    tf_ssec(obj)
    msg := sprintf("an object in %s is copied with SSE-C (a customer-provided key), not a KMS key", [tf_bucket_label(bname)])
} else := msg {
    alg := object.get(obj, "server_side_encryption", null)
    tf_known(alg)
    not tf_kms_algorithms[alg]
    not tf_sse_s3_allowed(alg, bname)
    msg := sprintf("an object in %s is uploaded with %s, not a KMS key", [tf_bucket_label(bname), alg])
} else := msg {
    alg := object.get(obj, "server_side_encryption", null)
    tf_kms_algorithms[alg]
    not tf_set(object.get(obj, "kms_key_id", null))
    msg := sprintf("an object in %s is uploaded with %s and no kms_key_id, so S3 uses the AWS managed key aws/s3", [tf_bucket_label(bname), alg])
} else := msg {
    msg := tf_key_problem(object.get(obj, "kms_key_id", null), bname, sprintf("an object in %s", [tf_bucket_label(bname)]))
}

WizPolicy[result] {
    document := input.document[i]
    otype := tf_object_types[_]
    obj := document.resource[otype][name]
    not tf_not_created(obj)
    bname := tf_bucket_names(i, object.get(obj, "bucket", null))[_]
    msg := tf_object_problem(obj, bname)

    result := {
        "documentId": document.id,
        "resourceType": otype,
        "resourceName": terraLib.get_resource_name(obj, name),
        "searchKey": sprintf("%s[%s]", [otype, name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("no SSE-C, and no server_side_encryption and kms_key_id (the bucket default applies) or server_side_encryption aws:kms or aws:kms:dsse with a kms_key_id authorized for the bucket: %v", [tf_expected_keys(bname)]),
        "keyActualValue": msg,
        "resourceTags": terraLib.get_resource_tags(obj),
    }
}
