package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized routes: source bucket name, then destination bucket ARN. Set
# replica_kms_key (key ARN, or null for none), owner_override (replicas owned
# by the destination account) and rtc (Replication Time Control required).
# Keep in sync with the cloud matcher and S3.C87.
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

# --- Logic ---
# --- toc-match begin: tf v1 ---
# A Terraform value that is still an unresolved reference ("${...}"). Treat
# it as unknown: never compare it with an allowlist as a string.
tocm_tf_unresolved(v) {
    is_string(v)
    contains(v, "${")
}
# --- toc-match end: tf v1 ---

# --- Bucket names ---
# A bucket is a literal name, or an aws_s3_bucket reference with a literal
# name. Unresolvable values are not judged.
literal(v) {
    is_string(v)
    not contains(v, "${")
    not regex.match(`^(aws_s3_bucket|aws_kms_key|aws_kms_alias|var|local|module|data)\.`, v)
}

source_name(document, rc) := rc.bucket {
    literal(rc.bucket)
}

source_name(document, rc) := n {
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket)\}?$`, rc.bucket, 1)[0]
    n := document.resource.aws_s3_bucket[m[1]].bucket
    literal(n)
}

config_source(document, cfg) := source_name(document, cfg.resource) {
    cfg.type == "aws_s3_bucket_replication_configuration"
}

config_source(document, cfg) := cfg.resource.bucket {
    cfg.type == "aws_s3_bucket"
    literal(cfg.resource.bucket)
}

destination_arn(document, dest) := dest.bucket {
    literal(dest.bucket)
}

destination_arn(document, dest) := sprintf("arn:aws:s3:::%s", [n]) {
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.arn\}?$`, dest.bucket, 1)[0]
    n := document.resource.aws_s3_bucket[m[1]].bucket
    literal(n)
}

# --- Replication configurations ---
# Inline blocks are read into the standalone resource's shape. An inline
# metrics or replication_time block with no status is Enabled (the default).
block(v) := terraLib.getValueArrayOrObject(v)

inline_block(v) := b {
    b := block(v)
    is_object(b)
}

# Keeps the keys that are set, so an unset inline argument stays unset.
set_keys(o) := {k: v | v := o[k]; v != null}

inline_kms_status(v) := "Enabled" {
    v == true
} else := "Enabled" {
    is_string(v)
    lower(v) == "true"
} else := v {
    tocm_tf_unresolved(v)
} else := "Disabled"

inline_selection(r) := {"sse_kms_encrypted_objects": {"status": inline_kms_status(o.enabled)}} {
    o := inline_block(inline_block(r.source_selection_criteria).sse_kms_encrypted_objects)
    o.enabled != null
} else := null

inline_encryption(d) := {"replica_kms_key_id": d.replica_kms_key_id} {
    d.replica_kms_key_id != null
} else := null

inline_status_block(d, key) := {"status": object.get(b, "status", "Enabled")} {
    b := inline_block(d[key])
} else := null

inline_destination(r) := set_keys({
    "bucket": object.get(d, "bucket", null),
    "account": object.get(d, "account_id", null),
    "encryption_configuration": inline_encryption(d),
    "access_control_translation": object.get(d, "access_control_translation", null),
    "replication_time": inline_status_block(d, "replication_time"),
    "metrics": inline_status_block(d, "metrics"),
}) {
    d := inline_block(r.destination)
} else := {}

inline_rule(r) := set_keys({
    "id": object.get(r, "id", null),
    "status": object.get(r, "status", null),
    "source_selection_criteria": inline_selection(r),
    "destination": inline_destination(r),
    "tf_dynamic_paths": tf_dynamic_paths(r),
})

inline_config(ic) := {"rule": [inline_rule(r) |
    r := terraLib.getArray(object.get(ic, "rules", []))[_]
    is_object(r)
]}

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

# The dynamic block's searchKey, or "" when every rule is written out.
tf_dynamic_key(b, label, key) := key {
    tf_dynamic(b, label)
} else := ""

# `generated` is an inline block that a dynamic block generates whole.
replication_configs(document) := standalone | inline | generated {
    standalone := {cfg |
        rc := document.resource.aws_s3_bucket_replication_configuration[name]
        not tf_not_created(rc)
        cfg := {
            "type": "aws_s3_bucket_replication_configuration",
            "name": name,
            "resource": rc,
            "rule_key": sprintf("aws_s3_bucket_replication_configuration[%s].rule", [name]),
            "config": rc,
            "dynamic_key": tf_dynamic_key(rc, "rule", sprintf("aws_s3_bucket_replication_configuration[%s].dynamic.rule", [name])),
        }
    }
    inline := {cfg |
        b := document.resource.aws_s3_bucket[name]
        not tf_not_created(b)
        ic := inline_block(b.replication_configuration)
        cfg := {
            "type": "aws_s3_bucket",
            "name": name,
            "resource": b,
            "rule_key": sprintf("aws_s3_bucket[%s].replication_configuration.rules", [name]),
            "config": inline_config(ic),
            "dynamic_key": tf_dynamic_key(ic, "rules", sprintf("aws_s3_bucket[%s].replication_configuration.dynamic.rules", [name])),
        }
    }
    generated := {cfg |
        b := document.resource.aws_s3_bucket[name]
        not tf_not_created(b)
        tf_dynamic(b, "replication_configuration")
        cfg := {
            "type": "aws_s3_bucket",
            "name": name,
            "resource": b,
            "rule_key": sprintf("aws_s3_bucket[%s].dynamic.replication_configuration", [name]),
            "config": {"rule": []},
            "dynamic_key": sprintf("aws_s3_bucket[%s].dynamic.replication_configuration", [name]),
        }
    }
}

# Rule blocks the route checks read, keyed by their parent block.
tf_judged_blocks := {
    "destination": {"encryption_configuration", "access_control_translation", "replication_time", "metrics"},
    "source_selection_criteria": {"sse_kms_encrypted_objects"},
}

# Paths of judged blocks that a dynamic block generates. Inline rules carry
# them precomputed, since conversion drops their dynamic blocks.
tf_dynamic_paths(rule) := {k | tf_judged_blocks[k]; tf_dynamic(rule, k)} | {concat(".", [k, l]) |
    nested := tf_judged_blocks[k]
    l := nested[_]
    tf_dynamic(block(rule[k]), l)
}

rule_dynamic_paths(rule) := rule.tf_dynamic_paths {
    rule.tf_dynamic_paths
} else := tf_dynamic_paths(rule)

tf_route_paths(route) := {"destination.encryption_configuration", "destination.access_control_translation"} | kms | rtc {
    kms := {p | setting(route, "replica_kms_key", null) != null; p := {"source_selection_criteria", "source_selection_criteria.sse_kms_encrypted_objects"}[_]}
    rtc := {p | setting(route, "rtc", false) == true; p := {"destination.replication_time", "destination.metrics"}[_]}
}

# --- Rule settings ---
tf_rule_label(rule, idx) := sprintf("rule '%s'", [rule.id]) {
    is_string(rule.id)
    rule.id != ""
} else := sprintf("rule %d", [idx])

setting(route, key, fallback) := object.get(route, key, fallback)

tf_replica_key(dest) := k {
    k := block(dest.encryption_configuration).replica_kms_key_id
    is_string(k)
    k != ""
}

tf_kms_objects_replicated(rule) {
    tf_status_enabled_or_unresolved(block(rule.source_selection_criteria).sse_kms_encrypted_objects)
}

tf_owner_overridden(dest) {
    block(dest.access_control_translation).owner == "Destination"
}

# An owner given by reference is known only at apply and is not judged.
tf_owner_unresolved(dest) {
    tocm_tf_unresolved(block(dest.access_control_translation).owner)
}

tf_rtc_enabled(dest) {
    tf_status_enabled_or_unresolved(dest.replication_time)
    tf_status_enabled_or_unresolved(dest.metrics)
}

# A status given by reference is known only at apply and is not judged.
tf_status_enabled_or_unresolved(b) {
    lower(block(b).status) == "enabled"
}

tf_status_enabled_or_unresolved(b) {
    tocm_tf_unresolved(block(b).status)
}

# Problems with one enabled rule of an authorized source bucket.
rule_problems(document, allowed, rule, idx) := target | enc | own | rtc {
    dest := block(rule.destination)
    darn := destination_arn(document, dest)
    target := {sprintf("%s replicates to unauthorized destination %s", [tf_rule_label(rule, idx), darn]) | not allowed[darn]}
    route := object.get(allowed, darn, {})
    expected_key := setting(route, "replica_kms_key", null)
    enc := {msg |
        allowed[darn]
        expected_key != null
        not tf_kms_objects_replicated(rule)
        msg := sprintf("%s does not replicate SSE-KMS objects (source_selection_criteria.sse_kms_encrypted_objects)", [tf_rule_label(rule, idx)])
    } | {msg |
        allowed[darn]
        expected_key != null
        key := object.get(block(object.get(dest, "encryption_configuration", {})), "replica_kms_key_id", "")
        literal(key)
        key != expected_key
        msg := sprintf("%s encrypts replicas with %s instead of %s", [tf_rule_label(rule, idx), key, expected_key])
    } | {msg |
        allowed[darn]
        expected_key != null
        not tf_replica_key(dest)
        msg := sprintf("%s names no replica KMS key; expected %s", [tf_rule_label(rule, idx), expected_key])
    } | {msg |
        allowed[darn]
        expected_key == null
        key := tf_replica_key(dest)
        msg := sprintf("%s encrypts replicas with %s but the route expects no replica key", [tf_rule_label(rule, idx), key])
    }
    own := {msg |
        allowed[darn]
        setting(route, "owner_override", false) == true
        not tf_owner_overridden(dest)
        not tf_owner_unresolved(dest)
        msg := sprintf("%s does not pass replica ownership to the destination account", [tf_rule_label(rule, idx)])
    } | {msg |
        allowed[darn]
        setting(route, "owner_override", false) == false
        tf_owner_overridden(dest)
        msg := sprintf("%s passes replica ownership to the destination account, which the route does not expect", [tf_rule_label(rule, idx)])
    }
    rtc := {msg |
        allowed[darn]
        setting(route, "rtc", false) == true
        not tf_rtc_enabled(dest)
        msg := sprintf("%s does not enable Replication Time Control with metrics", [tf_rule_label(rule, idx)])
    }
}

# A rule whose destination, or a block its route needs, comes from a dynamic
# block cannot be judged and is reported.
tf_rule_issues(document, allowed, rule, idx) := {msg} {
    rule_dynamic_paths(rule)["destination"]
    msg := sprintf("%s has its destination generated by a dynamic block, which cannot be judged", [tf_rule_label(rule, idx)])
} else := {msg} {
    route := allowed[destination_arn(document, block(rule.destination))]
    paths := rule_dynamic_paths(rule) & tf_route_paths(route)
    count(paths) > 0
    msg := sprintf("%s has %s generated by a dynamic block, which cannot be judged", [tf_rule_label(rule, idx), concat(", ", sort([p | p := paths[_]]))])
} else := rule_problems(document, allowed, rule, idx)

# One finding per enabled rule. Unlisted buckets are left to S3.C87.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    allowed := authorized_replications[config_source(document, cfg)]
    rule := terraLib.getArray(cfg.config.rule)[idx]
    lower(rule.status) == "enabled"
    issues := tf_rule_issues(document, allowed, rule, idx)
    count(issues) > 0

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": sprintf("%s[%d]", [cfg.rule_key, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "each enabled rule must target an authorized destination for this bucket, with the route's replica KMS key (and SSE-KMS objects replicated), replica ownership and Replication Time Control settings",
        "keyActualValue": concat("; ", sort([p | p := issues[_]])),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}

# Dynamic rules cannot be checked against routes, so the bucket is reported.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    cfg.dynamic_key != ""
    source := config_source(document, cfg)
    authorized_replications[source]

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": cfg.dynamic_key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": "each replication rule of an authorized bucket written out, so it can be checked against the bucket's authorized routes",
        "keyActualValue": sprintf("bucket '%s' has replication rules generated by a dynamic block, which cannot be judged", [source]),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}
