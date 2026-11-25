package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized replication routes: source bucket name, then each destination
# bucket ARN and its expected settings. This rule reads only the source names.
# Keep in sync with the cloud matcher and S3.C88.
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
# --- Source bucket ---
# A source is a literal name, or an aws_s3_bucket reference with a literal name.
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

config_source(document, cfg) := source_name(document, cfg.resource) {
    cfg.type == "aws_s3_bucket_replication_configuration"
}

config_source(document, cfg) := cfg.resource.bucket {
    cfg.type == "aws_s3_bucket"
    literal(cfg.resource.bucket)
}

# --- Replication configurations ---
# The inline block names its rules `rules`; it is read into the standalone
# resource's `rule` shape.
inline_block(v) := b {
    b := terraLib.getValueArrayOrObject(v)
    is_object(b)
}

inline_config(ic) := {"rule": [{"status": object.get(r, "status", "")} |
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
            "source_key": sprintf("aws_s3_bucket_replication_configuration[%s].bucket", [name]),
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
            "source_key": sprintf("aws_s3_bucket[%s].replication_configuration", [name]),
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
            "source_key": sprintf("aws_s3_bucket[%s].dynamic.replication_configuration", [name]),
            "config": {"rule": []},
            "dynamic_key": sprintf("aws_s3_bucket[%s].dynamic.replication_configuration", [name]),
        }
    }
}

tf_replication_enabled(rc) {
    lower(terraLib.getArray(rc.rule)[_].status) == "enabled"
}

# A bucket whose name cannot be resolved statically is not judged.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    tf_replication_enabled(cfg.config)
    source := config_source(document, cfg)
    not authorized_replications[source]

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": cfg.source_key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("only authorized buckets may have replication enabled: %v", [sort([b | authorized_replications[b]])]),
        "keyActualValue": sprintf("bucket '%s' has replication enabled but is not authorized to replicate", [source]),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}

# Dynamic rules may enable replication, so an unlisted bucket is reported.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    cfg.dynamic_key != ""
    not tf_replication_enabled(cfg.config)
    source := config_source(document, cfg)
    not authorized_replications[source]

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": cfg.dynamic_key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("only authorized buckets may have replication enabled: %v. Write replication rules out so their status can be judged", [sort([b | authorized_replications[b]])]),
        "keyActualValue": sprintf("bucket '%s' is not authorized to replicate and has replication rules generated by a dynamic block, which cannot be judged", [source]),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}
