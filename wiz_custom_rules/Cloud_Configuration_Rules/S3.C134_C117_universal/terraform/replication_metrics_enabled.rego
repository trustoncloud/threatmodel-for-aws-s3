package wiz

import data.generic.terraform as terraLib

# --- Logic ---
rule_metrics_enabled(rule) {
    dest := terraLib.getValueArrayOrObject(rule.destination)
    metrics := terraLib.getValueArrayOrObject(dest.metrics)
    metrics.status == "Enabled"
}

# Universal: every replication rule must enable destination metrics.
WizPolicy[result] {
    document := input.document[i]
    rc := document.resource.aws_s3_bucket_replication_configuration[name]
    rule := terraLib.getArray(rc.rule)[ridx]
    not rule_metrics_enabled(rule)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_replication_configuration",
        "resourceName": terraLib.get_resource_name(rc, name),
        "searchKey": sprintf("aws_s3_bucket_replication_configuration[%s].rule[%d].destination.metrics", [name, ridx]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "every replication rule must set destination.metrics.status to Enabled",
        "keyActualValue": sprintf("rule[%d] has metrics missing or not Enabled", [ridx]),
        "resourceTags": terraLib.get_resource_tags(rc),
    }
}
