package wiz

import data.generic.terraform as terraLib

# --- Policy helpers ---
is_s3_service(sn) { endswith(sn, ".s3") }

inline_statements(ep) := {s |
    is_string(ep.policy)
    s := terraLib.getStatement(json.unmarshal(ep.policy))[_]
}

assoc_statements(document, ep, name) := {s |
    p := document.resource.aws_vpc_endpoint_policy[pn]
    terraLib.associatedResources(p, ep, pn, name, "vpc_endpoint_id", "id")
    is_string(p.policy)
    s := terraLib.getStatement(json.unmarshal(p.policy))[_]
}

endpoint_statements(document, ep, name) := inline_statements(ep) | assoc_statements(document, ep, name)

is_org_key("aws:principalorgid")
is_org_key("aws:principalorgpaths")
is_org_key("aws:principalaccount")

tf_has_org_restriction(document, ep, name) {
    stmt := endpoint_statements(document, ep, name)[_]
    stmt.Effect == "Deny"
    conditions := stmt.Condition[operator]
    contains(lower(operator), "stringnotequals")
    val := conditions[key]
    is_org_key(lower(key))
    val != null
}

# --- Data-source (aws_iam_policy_document) form ---
ref_to_ds(document, ep, name, dsName) {
    is_string(ep.policy)
    contains(ep.policy, dsName)
}

ref_to_ds(document, ep, name, dsName) {
    p := document.resource.aws_vpc_endpoint_policy[pn]
    terraLib.associatedResources(p, ep, pn, name, "vpc_endpoint_id", "id")
    is_string(p.policy)
    contains(p.policy, dsName)
}

ds_statements(document, ep, name) := {s |
    ds := document.data.aws_iam_policy_document[dsName]
    ref_to_ds(document, ep, name, dsName)
    s := terraLib.getArray(ds.statement)[_]
}

tf_has_org_restriction(document, ep, name) {
    stmt := ds_statements(document, ep, name)[_]
    lower(stmt.effect) == "deny"
    c := terraLib.getArray(stmt.condition)[_]
    contains(lower(c.test), "stringnotequals")
    is_org_key(lower(c.variable))
    count(terraLib.getArray(c.values)) > 0
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not tf_has_org_restriction(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must deny access with StringNotEquals on an organization condition key", [name]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy does not restrict access by organization", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}
