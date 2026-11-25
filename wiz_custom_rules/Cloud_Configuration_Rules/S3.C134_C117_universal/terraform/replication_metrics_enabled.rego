package wiz

import data.generic.terraform as terraLib

# --- Logic ---
# --- toc-match begin: tf v1 ---
# A Terraform value that is still an unresolved reference ("${...}"). Treat
# it as unknown: never compare it with an allowlist as a string.
tocm_tf_unresolved(v) {
    is_string(v)
    contains(v, "${")
}
# --- toc-match end: tf v1 ---

# --- Replication configurations ---
# Inline replication_configuration rules (`rules`) are read into the standalone
# `rule` shape. An inline metrics block with no status is Enabled.
inline_block(v) := b {
    b := terraLib.getValueArrayOrObject(v)
    is_object(b)
}

inline_metrics(r) := {"metrics": {"status": object.get(m, "status", "Enabled")}} {
    m := inline_block(inline_block(r.destination).metrics)
} else := {}

inline_config(ic) := {"rule": [{"destination": inline_metrics(r), "tf_dynamic_paths": tf_dynamic_paths(r)} |
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

# searchKey of the dynamic block generating a configuration's rules, or "".
tf_dynamic_key(b, label, key) := key {
    tf_dynamic(b, label)
} else := ""

# An inline block that a dynamic block generates whole has no rules to read.
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

# Rule blocks the metrics check reads, keyed by their parent block.
tf_judged_blocks := {
    "destination": {"metrics"},
}

# Judged blocks a dynamic block generates. Inline rules carry these paths.
tf_dynamic_paths(rule) := {k | tf_judged_blocks[k]; tf_dynamic(rule, k)} | {concat(".", [k, l]) |
    nested := tf_judged_blocks[k]
    l := nested[_]
    tf_dynamic(terraLib.getValueArrayOrObject(rule[k]), l)
}

rule_dynamic_paths(rule) := rule.tf_dynamic_paths {
    rule.tf_dynamic_paths
} else := tf_dynamic_paths(rule)

rule_metrics_enabled(rule) {
    dest := terraLib.getValueArrayOrObject(rule.destination)
    metrics := terraLib.getValueArrayOrObject(dest.metrics)
    metrics.status == "Enabled"
}

# A metrics status given by reference is known only at apply and is not judged.
tf_metrics_status_unresolved(rule) {
    dest := terraLib.getValueArrayOrObject(rule.destination)
    metrics := terraLib.getValueArrayOrObject(dest.metrics)
    tocm_tf_unresolved(metrics.status)
}

# Universal: every replication rule must enable destination metrics.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    rule := terraLib.getArray(cfg.config.rule)[ridx]
    count(rule_dynamic_paths(rule)) == 0
    not rule_metrics_enabled(rule)
    not tf_metrics_status_unresolved(rule)

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": sprintf("%s[%d].destination.metrics", [cfg.rule_key, ridx]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "every replication rule must set destination.metrics.status to Enabled",
        "keyActualValue": sprintf("rule[%d] has metrics missing or not Enabled", [ridx]),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}

# A rule with a dynamic destination or metrics block cannot be judged.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    rule := terraLib.getArray(cfg.config.rule)[ridx]
    paths := rule_dynamic_paths(rule)
    count(paths) > 0

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": sprintf("%s[%d].destination.metrics", [cfg.rule_key, ridx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "every replication rule must set destination.metrics.status to Enabled in blocks the source shows",
        "keyActualValue": sprintf("rule[%d] has %s generated by a dynamic block, which cannot be judged", [ridx, concat(", ", sort([p | p := paths[_]]))]),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}

# Rules generated by a dynamic block cannot be judged and are reported.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    cfg.dynamic_key != ""

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": cfg.dynamic_key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": "every replication rule written out with destination.metrics.status set to Enabled",
        "keyActualValue": "replication rules are generated by a dynamic block, which cannot be judged",
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}
