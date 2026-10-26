package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_buckets := {
    "arn:aws:s3:::authorized-bucket",
}

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

has_inline_policy(ep) { is_string(ep.policy) }

has_assoc_policy(document, ep, name) {
    p := document.resource.aws_vpc_endpoint_policy[pn]
    terraLib.associatedResources(p, ep, pn, name, "vpc_endpoint_id", "id")
    is_string(p.policy)
}

has_any_policy(document, ep, name) { has_inline_policy(ep) }
has_any_policy(document, ep, name) { has_assoc_policy(document, ep, name) }

resource_authorized(res) {
    authorized_buckets[res]
}

resource_authorized(res) {
    endswith(res, "/*")
    base := substring(res, 0, count(res) - 2)
    authorized_buckets[base]
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

# effect is optional in the data source and defaults to Allow.
ds_effect_allow(stmt) { not stmt.effect }
ds_effect_allow(stmt) { lower(stmt.effect) == "allow" }

tf_allowed_resources(document, ep, name) := res {
    res := {r |
        stmt := endpoint_statements(document, ep, name)[_]
        stmt.Effect == "Allow"
        r := stmt.Resource
        is_string(r)
    } | {r |
        stmt := endpoint_statements(document, ep, name)[_]
        stmt.Effect == "Allow"
        r := stmt.Resource[_]
    } | {r |
        stmt := ds_statements(document, ep, name)[_]
        ds_effect_allow(stmt)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Logic ---
# Fail 1: S3 endpoint with no policy defaults to full access.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not has_any_policy(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must limit access to authorized buckets: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' has no policy, so it can access any bucket", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 2: an Allow statement grants a resource outside the authorized buckets.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    res := tf_allowed_resources(document, ep, name)[_]
    not resource_authorized(res)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' Allow statements must target only authorized buckets: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' allows access to unauthorized resource '%s'", [name, res]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}
