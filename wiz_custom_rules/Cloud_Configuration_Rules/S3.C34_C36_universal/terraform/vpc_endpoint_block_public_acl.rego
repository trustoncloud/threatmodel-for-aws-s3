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

covers_put_object_acl(action) { action == "s3:PutObjectAcl" }
covers_put_object_acl(action) { action == "s3:*" }
covers_put_object_acl(action) { action == "*" }
covers_put_object_acl(action) { action[_] == "s3:PutObjectAcl" }
covers_put_object_acl(action) { action[_] == "s3:*" }
covers_put_object_acl(action) { action[_] == "*" }

is_public_scalar(v) { v == "public-read" }
is_public_scalar(v) { v == "public-read-write" }

tf_targets_public_acl(stmt) {
    conditions := stmt.Condition[operator]
    val := conditions[key]
    lower(key) == "s3:x-amz-acl"
    is_public_scalar(val)
}

tf_targets_public_acl(stmt) {
    conditions := stmt.Condition[operator]
    val := conditions[key]
    lower(key) == "s3:x-amz-acl"
    is_public_scalar(val[_])
}

blocks_public_acl(document, ep, name) {
    stmt := endpoint_statements(document, ep, name)[_]
    stmt.Effect == "Deny"
    covers_put_object_acl(stmt.Action)
    tf_targets_public_acl(stmt)
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

covers_put_object_acl_hcl(stmt) { terraLib.getArray(stmt.actions)[_] == "s3:PutObjectAcl" }
covers_put_object_acl_hcl(stmt) { terraLib.getArray(stmt.actions)[_] == "s3:*" }
covers_put_object_acl_hcl(stmt) { terraLib.getArray(stmt.actions)[_] == "*" }

ds_public_acl_condition(c) {
    lower(c.variable) == "s3:x-amz-acl"
    is_public_scalar(terraLib.getArray(c.values)[_])
}

blocks_public_acl(document, ep, name) {
    stmt := ds_statements(document, ep, name)[_]
    lower(stmt.effect) == "deny"
    covers_put_object_acl_hcl(stmt)
    ds_public_acl_condition(terraLib.getArray(stmt.condition)[_])
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not blocks_public_acl(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must deny s3:PutObjectAcl with a public canned ACL", [name]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy does not block public object ACLs", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}
