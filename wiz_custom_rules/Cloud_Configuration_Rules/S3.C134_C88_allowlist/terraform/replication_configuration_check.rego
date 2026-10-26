package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized replication routes: source bucket name, then each destination
# bucket ARN it may replicate to and that route's expected settings:
#   replica_kms_key  KMS key ARN for replicas of SSE-KMS objects, or null when
#                    the route must not name a replica key
#   owner_override   whether replica ownership passes to the destination account
#   rtc              whether S3 Replication Time Control must be enabled
# S3.C87 checks which buckets may replicate. Keep in sync with the cloud matcher
# and S3.C87.
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

# --- Bucket names ---
# Buckets are named as literals or as references (interpolated or bare) to an
# aws_s3_bucket whose `bucket` is a literal. Unresolvable values are not judged.
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

destination_arn(document, dest) := dest.bucket {
    literal(dest.bucket)
}

destination_arn(document, dest) := sprintf("arn:aws:s3:::%s", [n]) {
    m := regex.find_all_string_submatch_n(`^(?:\$\{)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.arn\}?$`, dest.bucket, 1)[0]
    n := document.resource.aws_s3_bucket[m[1]].bucket
    literal(n)
}

# --- Rule settings ---
block(v) := terraLib.getValueArrayOrObject(v)

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
    lower(block(block(rule.source_selection_criteria).sse_kms_encrypted_objects).status) == "enabled"
}

tf_owner_overridden(dest) {
    block(dest.access_control_translation).owner == "Destination"
}

tf_rtc_enabled(dest) {
    lower(block(dest.replication_time).status) == "enabled"
    lower(block(dest.metrics).status) == "enabled"
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

# --- Logic ---
# One finding per enabled rule that differs from its route. Buckets not on the
# list are S3.C87's finding, not this rule's.
WizPolicy[result] {
    document := input.document[i]
    rc := document.resource.aws_s3_bucket_replication_configuration[name]
    allowed := authorized_replications[source_name(document, rc)]
    rule := terraLib.getArray(rc.rule)[idx]
    lower(rule.status) == "enabled"
    issues := rule_problems(document, allowed, rule, idx)
    count(issues) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_replication_configuration",
        "resourceName": terraLib.get_resource_name(rc, name),
        "searchKey": sprintf("aws_s3_bucket_replication_configuration[%s].rule[%d]", [name, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "each enabled rule must target an authorized destination for this bucket, with the route's replica KMS key (and SSE-KMS objects replicated), replica ownership and Replication Time Control settings",
        "keyActualValue": concat("; ", sort([p | p := issues[_]])),
        "resourceTags": terraLib.get_resource_tags(rc),
    }
}
