package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized replication roles: source bucket name, then the IAM role ARNs it
# may use. A bucket that replicates with no entry fails. A role listed under
# many buckets is approved for each of them.
authorized_replication_roles := {
    "authorized-source-bucket": {
        "arn:aws:iam::123456789012:role/authorized-replication-role",
    },
}

# --- Logic ---
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
# The standalone resource and the inline block both carry the role as `role`.
inline_block(v) := b {
    b := terraLib.getValueArrayOrObject(v)
    is_object(b)
}

inline_config(ic) := {"role": ic.role} {
    ic.role != null
} else := {}

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

# The role sits outside the rules, so dynamic rules leave it visible. An
# inline block that a dynamic block generates whole hides it.
replication_configs(document) := standalone | inline | generated {
    standalone := {cfg |
        rc := document.resource.aws_s3_bucket_replication_configuration[name]
        not tf_not_created(rc)
        cfg := {
            "type": "aws_s3_bucket_replication_configuration",
            "name": name,
            "resource": rc,
            "role_key": sprintf("aws_s3_bucket_replication_configuration[%s].role", [name]),
            "config": rc,
            "generated": false,
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
            "role_key": sprintf("aws_s3_bucket[%s].replication_configuration.role", [name]),
            "config": inline_config(ic),
            "generated": false,
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
            "role_key": sprintf("aws_s3_bucket[%s].dynamic.replication_configuration", [name]),
            "config": {},
            "generated": true,
        }
    }
}

# --- Role check ---
role_authorized_for(source, role) {
    tocm_arn_allowed(role, authorized_replication_roles[source])
}

role_listed_for_any_bucket(role) {
    tocm_arn_allowed(role, authorized_replication_roles[_])
}

# When the source bucket is known only at apply, a role listed for no bucket
# fails; one listed for some bucket is left to the cloud check.
role_issue(document, cfg, role) := sprintf("bucket '%s' replicates with role '%s' but has no entry in authorized_replication_roles", [source, role]) {
    source := config_source(document, cfg)
    not authorized_replication_roles[source]
} else := sprintf("role '%s' is not authorized for bucket '%s'", [role, source]) {
    source := config_source(document, cfg)
    not role_authorized_for(source, role)
} else := sprintf("role '%s' is not authorized for any bucket", [role]) {
    not config_source(document, cfg)
    not role_listed_for_any_bucket(role)
}

# A role given by reference is known only at apply and is not compared.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    terraLib.validKey(cfg.config, "role")
    role := cfg.config.role
    not tocm_tf_unresolved(role)
    issue := role_issue(document, cfg, role)

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": cfg.role_key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": "role must be an IAM role ARN listed for the source bucket in authorized_replication_roles",
        "keyActualValue": issue,
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}

tf_bucket_text(document, cfg) := sprintf("bucket '%s'", [source]) {
    source := config_source(document, cfg)
} else := sprintf("aws_s3_bucket.%s", [cfg.name])

# A generated inline block hides its role, so the bucket is reported.
WizPolicy[result] {
    document := input.document[i]
    cfg := replication_configs(document)[_]
    cfg.generated

    result := {
        "documentId": document.id,
        "resourceType": cfg.type,
        "resourceName": terraLib.get_resource_name(cfg.resource, cfg.name),
        "searchKey": cfg.role_key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": "role must be an IAM role ARN listed for the source bucket in authorized_replication_roles, written in a replication_configuration block the source shows",
        "keyActualValue": sprintf("%s has its replication_configuration generated by a dynamic block, so its role cannot be judged", [tf_bucket_text(document, cfg)]),
        "resourceTags": terraLib.get_resource_tags(cfg.resource),
    }
}
