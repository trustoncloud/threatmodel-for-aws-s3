package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_orgs := {
    "o-exampleorgid",
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

is_org_key("aws:principalorgid")
is_org_key("aws:principalorgpaths")
is_org_key("aws:principalaccount")

condition_values(v) := {v} { is_string(v) }
condition_values(v) := {x | x := v[_]} { is_array(v) }

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

tf_enforced_orgs(document, ep, name) := orgs {
    orgs := {org |
        stmt := endpoint_statements(document, ep, name)[_]
        stmt.Effect == "Deny"
        conditions := stmt.Condition[operator]
        contains(lower(operator), "stringnotequals")
        val := conditions[key]
        is_org_key(lower(key))
        org := condition_values(val)[_]
    } | {org |
        stmt := ds_statements(document, ep, name)[_]
        lower(stmt.effect) == "deny"
        c := terraLib.getArray(stmt.condition)[_]
        contains(lower(c.test), "stringnotequals")
        is_org_key(lower(c.variable))
        org := condition_values(c.values)[_]
    }
}

tf_has_enforcement(document, ep, name) {
    count(tf_enforced_orgs(document, ep, name)) > 0
}

# --- Logic ---
# Fail 1: S3 endpoint with no organization restriction at all.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not tf_has_enforcement(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must restrict access to authorized organizations: %v", [name, authorized_orgs]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy does not restrict access by organization", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 2: restriction exists but allows an organization outside the set.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    unauth := tf_enforced_orgs(document, ep, name) - authorized_orgs
    count(unauth) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must allow only authorized organizations: %v", [name, authorized_orgs]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy allows unauthorized organization(s): %v", [name, unauth]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}
