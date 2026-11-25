package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Exact bucket name to its Object Lock default: mode, GOVERNANCE or
# COMPLIANCE in capitals, and min_days from your retention policy (a year is
# 365 days). Others are not assessed. Keep in sync with the cloud matcher.
worm_buckets := {
    "worm-records-bucket": {"mode": "COMPLIANCE", "min_days": 365},
    "worm-audit-bucket": {"mode": "GOVERNANCE", "min_days": 730},
}

# --- Logic ---
# Object Lock is set on the bucket, inline or standalone. A bucket named only
# at apply cannot be matched with worm_buckets and is not judged.

# A value written in the source, known before apply.
tf_known(v) {
    is_string(v)
    trim_space(v) != ""
    not tocm_tf_unresolved(v)
}

# --- Bucket names ---
# A bucket is named by a literal or a reference to a literal aws_s3_bucket.
tf_literal_name(v) {
    tf_known(v)
    not regex.match(`^(aws_s3_bucket|var|local|module|data)\.`, v)
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

# --- Retention period ---
# A number may also be written as a quoted literal.
tf_number(v) := v {
    is_number(v)
} else := n {
    tf_known(v)
    regex.match(`^\s*[0-9]+\s*$`, v)
    n := to_number(trim_space(v))
}

# Days and years cannot both be set; a year counts 365 days.
tf_period_days(dr) := d {
    d := tf_number(object.get(dr, "days", null))
} else := d {
    d := tf_number(object.get(dr, "years", null)) * 365
}

tf_period_label(dr) := "1 day" {
    tf_number(object.get(dr, "days", null)) == 1
} else := sprintf("%v days", [tf_number(dr.days)]) {
    tf_number(object.get(dr, "days", null))
} else := sprintf("1 year (%v days)", [tf_period_days(dr)]) {
    tf_number(object.get(dr, "years", null)) == 1
} else := sprintf("%v years (%v days)", [tf_number(dr.years), tf_period_days(dr)])

tf_period_unresolved(dr) {
    tocm_tf_unresolved(object.get(dr, "days", null))
}

tf_period_unresolved(dr) {
    tocm_tf_unresolved(object.get(dr, "years", null))
}

tf_true(v) {
    v == true
}

tf_true(v) {
    tf_known(v)
    lower(trim_space(v)) == "true"
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

# --- Default retention settings ---
# Each rule of a created Object Lock configuration for a WORM bucket.
tf_lock_rules[entry] {
    document := input.document[i]
    cfg := document.resource.aws_s3_bucket_object_lock_configuration[name]
    not tf_not_created(cfg)
    bname := tf_bucket_names(i, object.get(cfg, "bucket", null))[_]
    worm_buckets[bname]
    rule := terraLib.getArray(object.get(cfg, "rule", []))[_]
    is_object(rule)
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket_object_lock_configuration",
        "name": name,
        "resource": cfg,
        "bucket": bname,
        "rule": rule,
        "key": sprintf("aws_s3_bucket_object_lock_configuration[%s].rule", [name]),
    }
}

tf_lock_rules[entry] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    bname := object.get(b, "bucket", null)
    tf_literal_name(bname)
    worm_buckets[bname]
    rule := terraLib.getArray(object.get(tf_inline_blocks(b)[_], "rule", []))[_]
    is_object(rule)
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket",
        "name": name,
        "resource": b,
        "bucket": bname,
        "rule": rule,
        "key": sprintf("aws_s3_bucket[%s].object_lock_configuration.rule", [name]),
    }
}

tf_retentions[entry] {
    r := tf_lock_rules[_]
    dr := terraLib.getArray(object.get(r.rule, "default_retention", []))[_]
    is_object(dr)
    entry := {
        "document": r.document,
        "type": r.type,
        "name": r.name,
        "resource": r.resource,
        "bucket": r.bucket,
        "retention": dr,
        "key": sprintf("%s.default_retention", [r.key]),
    }
}

# --- Default retention generated by a dynamic block ---
# A dynamic block hides the default retention, so it is reported.
tf_worm_bucket(b) := bname {
    bname := object.get(b, "bucket", null)
    tf_literal_name(bname)
    worm_buckets[bname]
}

tf_dynamic_sources[entry] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    bname := tf_worm_bucket(b)
    tf_dynamic(b, "object_lock_configuration")
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket",
        "name": name,
        "resource": b,
        "bucket": bname,
        "key": sprintf("aws_s3_bucket[%s].dynamic.object_lock_configuration", [name]),
    }
}

tf_dynamic_sources[entry] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    bname := tf_worm_bucket(b)
    tf_dynamic(tf_inline_blocks(b)[_], "rule")
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket",
        "name": name,
        "resource": b,
        "bucket": bname,
        "key": sprintf("aws_s3_bucket[%s].object_lock_configuration.dynamic.rule", [name]),
    }
}

tf_dynamic_sources[entry] {
    document := input.document[i]
    cfg := document.resource.aws_s3_bucket_object_lock_configuration[name]
    not tf_not_created(cfg)
    bname := tf_bucket_names(i, object.get(cfg, "bucket", null))[_]
    worm_buckets[bname]
    tf_dynamic(cfg, "rule")
    entry := {
        "document": document.id,
        "type": "aws_s3_bucket_object_lock_configuration",
        "name": name,
        "resource": cfg,
        "bucket": bname,
        "key": sprintf("aws_s3_bucket_object_lock_configuration[%s].dynamic.rule", [name]),
    }
}

tf_dynamic_sources[entry] {
    r := tf_lock_rules[_]
    tf_dynamic(r.rule, "default_retention")
    entry := {
        "document": r.document,
        "type": r.type,
        "name": r.name,
        "resource": r.resource,
        "bucket": r.bucket,
        "key": sprintf("%s.dynamic.default_retention", [r.key]),
    }
}

# --- A bucket's own Object Lock ---
# A standalone configuration names the bucket by a reference in its module,
# or by the literal name, which matches across modules.
tf_linked_config(i, b, name) {
    cfg := input.document[j].resource.aws_s3_bucket_object_lock_configuration[_]
    not tf_not_created(cfg)
    ref := tf_bucket_ref(object.get(cfg, "bucket", null))
    ref == name
    tf_lookup_docs(j, "resource", "aws_s3_bucket", ref)[i]
}

tf_linked_config(i, b, name) {
    cfg := input.document[_].resource.aws_s3_bucket_object_lock_configuration[_]
    not tf_not_created(cfg)
    tf_literal_name(b.bucket)
    cfg.bucket == b.bucket
}

tf_inline_blocks(b) := [blk | blk := terraLib.getArray(object.get(b, "object_lock_configuration", []))[_]; is_object(blk)]

tf_lock_enabled(i, b, name) {
    tf_true(object.get(b, "object_lock_enabled", null))
}

tf_lock_enabled(i, b, name) {
    object.get(tf_inline_blocks(b)[_], "object_lock_enabled", null) == "Enabled"
}

tf_lock_enabled(i, b, name) {
    object.get(tf_inline_blocks(b)[_], "rule", null) != null
}

tf_lock_enabled(i, b, name) {
    tf_dynamic(b, "object_lock_configuration")
}

tf_lock_enabled(i, b, name) {
    tf_linked_config(i, b, name)
}

# object_lock_enabled given by reference is known only at apply.
tf_lock_unresolved(b) {
    tocm_tf_unresolved(object.get(b, "object_lock_enabled", null))
}

tf_has_default(i, b, name) {
    object.get(tf_inline_blocks(b)[_], "rule", null) != null
}

tf_has_default(i, b, name) {
    tf_dynamic(tf_inline_blocks(b)[_], "rule")
}

tf_has_default(i, b, name) {
    tf_dynamic(b, "object_lock_configuration")
}

# A standalone configuration without a rule is reported on that resource.
tf_has_default(i, b, name) {
    tf_linked_config(i, b, name)
}

tf_expected(bname) := sprintf("Object Lock enabled with a default retention in %s mode of at least %v days (a year counts 365 days)", [worm_buckets[bname].mode, worm_buckets[bname].min_days])

# A bucket requiring WORM without Object Lock.
WizPolicy[result] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    bname := object.get(b, "bucket", null)
    tf_literal_name(bname)
    worm_buckets[bname]
    not tf_lock_enabled(i, b, name)
    not tf_lock_unresolved(b)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(b, name),
        "searchKey": sprintf("aws_s3_bucket[%s].object_lock_enabled", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": tf_expected(bname),
        "keyActualValue": sprintf("bucket '%s' requires WORM but Object Lock is not enabled", [bname]),
        "resourceTags": terraLib.get_resource_tags(b),
    }
}

# A bucket requiring WORM with Object Lock but no default retention.
WizPolicy[result] {
    document := input.document[i]
    b := document.resource.aws_s3_bucket[name]
    not tf_not_created(b)
    bname := object.get(b, "bucket", null)
    tf_literal_name(bname)
    worm_buckets[bname]
    tf_lock_enabled(i, b, name)
    not tf_has_default(i, b, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(b, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": tf_expected(bname),
        "keyActualValue": sprintf("bucket '%s' requires WORM but Object Lock has no default retention (no aws_s3_bucket_object_lock_configuration rule)", [bname]),
        "resourceTags": terraLib.get_resource_tags(b),
    }
}

# A standalone configuration with no rule leaves no default retention.
WizPolicy[result] {
    document := input.document[i]
    cfg := document.resource.aws_s3_bucket_object_lock_configuration[name]
    not tf_not_created(cfg)
    bname := tf_bucket_names(i, object.get(cfg, "bucket", null))[_]
    worm_buckets[bname]
    object.get(cfg, "rule", null) == null
    not tf_dynamic(cfg, "rule")

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_object_lock_configuration",
        "resourceName": terraLib.get_resource_name(cfg, name),
        "searchKey": sprintf("aws_s3_bucket_object_lock_configuration[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": tf_expected(bname),
        "keyActualValue": sprintf("the Object Lock configuration of bucket '%s' has no rule, so it sets no default retention", [bname]),
        "resourceTags": terraLib.get_resource_tags(cfg),
    }
}

# A default retention in another mode.
WizPolicy[result] {
    entry := tf_retentions[_]
    mode := object.get(entry.retention, "mode", null)
    not tocm_tf_unresolved(mode)
    mode != worm_buckets[entry.bucket].mode

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": sprintf("%s.mode", [entry.key]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": tf_expected(entry.bucket),
        "keyActualValue": sprintf("bucket '%s' default retention mode is %v", [entry.bucket, mode]),
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}

# A default retention shorter than the minimum.
WizPolicy[result] {
    entry := tf_retentions[_]
    tf_period_days(entry.retention) < worm_buckets[entry.bucket].min_days

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": entry.key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": tf_expected(entry.bucket),
        "keyActualValue": sprintf("bucket '%s' default retention is %s, shorter than %v days", [entry.bucket, tf_period_label(entry.retention), worm_buckets[entry.bucket].min_days]),
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}

# A default retention with no period.
WizPolicy[result] {
    entry := tf_retentions[_]
    not tf_period_days(entry.retention)
    not tf_period_unresolved(entry.retention)

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": entry.key,
        "issueType": "MissingAttribute",
        "keyExpectedValue": tf_expected(entry.bucket),
        "keyActualValue": sprintf("bucket '%s' default retention sets neither days nor years", [entry.bucket]),
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}

# A default retention generated by a dynamic block.
WizPolicy[result] {
    entry := tf_dynamic_sources[_]

    result := {
        "documentId": entry.document,
        "resourceType": entry.type,
        "resourceName": terraLib.get_resource_name(entry.resource, entry.name),
        "searchKey": entry.key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("%s, written out so it can be read", [tf_expected(entry.bucket)]),
        "keyActualValue": sprintf("the Object Lock default of bucket '%s' is generated by a dynamic block, so it cannot be read", [entry.bucket]),
        "resourceTags": terraLib.get_resource_tags(entry.resource),
    }
}
