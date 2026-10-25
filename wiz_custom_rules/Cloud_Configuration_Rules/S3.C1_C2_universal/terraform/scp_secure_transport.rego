package wiz

import data.generic.terraform as terraLib

# Cloud matcher is N/A: SCPs are not an ingested Wiz native type. This
# Terraform matcher enforces the control at build time.
#
# Scope: only Service Control Policies. In an org with multiple SCPs, each is
# checked independently; keep the S3 secure-transport enforcement in the
# SCP(s) covered by this scan (or suppress on SCPs that serve another purpose).

# --- Policy helpers ---
is_scp(res) { res.type == "SERVICE_CONTROL_POLICY" }
is_scp(res) { not res.type }

covers_s3(action) { action == "s3:*" }
covers_s3(action) { action == "*" }
covers_s3(action) { action[_] == "s3:*" }
covers_s3(action) { action[_] == "*" }

# JSON-string content (heredoc or literal): standard IAM shape.
denies_insecure_json(stmt) { stmt.Condition.Bool["aws:SecureTransport"] == "false" }
denies_insecure_json(stmt) { stmt.Condition.Bool["aws:SecureTransport"] == false }

denies_old_tls_json(stmt) {
    v := stmt.Condition.NumericLessThan["s3:TlsVersion"]
    to_number(v) == 1.2
}

compliant_json(res) {
    is_string(res.content)
    stmt := terraLib.getStatement(json.unmarshal(res.content))[_]
    stmt.Effect == "Deny"
    covers_s3(stmt.Action)
    denies_insecure_json(stmt)
}

compliant_json(res) {
    is_string(res.content)
    stmt := terraLib.getStatement(json.unmarshal(res.content))[_]
    stmt.Effect == "Deny"
    covers_s3(stmt.Action)
    denies_old_tls_json(stmt)
}

# Data-source content (aws_iam_policy_document): lowercase HCL shape.
value_is(v, target) { v == target }
value_is(v, target) { v[_] == target }

ds_condition_ok(c) {
    contains(lower(c.test), "bool")
    lower(c.variable) == "aws:securetransport"
    value_is(c.values, "false")
}

ds_condition_ok(c) {
    contains(lower(c.test), "numericlessthan")
    lower(c.variable) == "s3:tlsversion"
    value_is(c.values, "1.2")
}

compliant_ds(document, res) {
    is_string(res.content)
    ds := document.data.aws_iam_policy_document[dsName]
    contains(res.content, dsName)
    stmt := terraLib.getArray(ds.statement)[_]
    lower(stmt.effect) == "deny"
    covers_s3(terraLib.getArray(stmt.actions)[_])
    ds_condition_ok(terraLib.getArray(stmt.condition)[_])
}

has_compliant_deny(document, res) { compliant_json(res) }
has_compliant_deny(document, res) { compliant_ds(document, res) }

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    res := document.resource.aws_organizations_policy[name]
    is_scp(res)
    not has_compliant_deny(document, res)

    result := {
        "documentId": document.id,
        "resourceType": "aws_organizations_policy",
        "resourceName": terraLib.get_resource_name(res, name),
        "searchKey": sprintf("aws_organizations_policy[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("SCP '%s' must Deny s3:* when aws:SecureTransport is false or s3:TlsVersion is below 1.2", [name]),
        "keyActualValue": sprintf("SCP '%s' does not deny insecure transport for S3", [name]),
        "resourceTags": terraLib.get_resource_tags(res),
    }
}
