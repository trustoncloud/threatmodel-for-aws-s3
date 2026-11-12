package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_principals := {
    "arn:aws:iam::123456789012:role/authorized-role",
    "arn:aws:iam::123456789012:root",
}

# --- Policy helpers ---
principal_values(v) := {v} { is_string(v) }
principal_values(v) := {x | x := v[_]} { is_array(v) }

# Principal types that name IAM principals: "AWS", and "*" for everyone.
granting_principal_types := {"aws", "*"}

# Statements of the bucket policy JSON. A policy built in a data source can
# arrive resolved, with Statements and Principals ({"<type>": [identifiers]})
# and no Effect when effect is left out, which defaults to Allow.
json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    doc := json.unmarshal(pol.policy)
}

json_effect_allow(stmt) { lower(object.get(stmt, "Effect", "Allow")) == "allow" }

json_principals(stmt) := everyone | aws | resolved {
    everyone := {"*" | stmt.Principal == "*"}
    aws := {p | p := principal_values(stmt.Principal.AWS)[_]}
    resolved := {p |
        v := stmt.Principals[t]
        granting_principal_types[lower(t)]
        p := principal_values(v)[_]
    }
}

# IAM principals granted access by Allow statements in the bucket policy JSON.
json_granted(pol) := {p |
    stmt := json_statements(pol)[_]
    json_effect_allow(stmt)
    p := json_principals(stmt)[_]
}

# From a policy-document data source: principals live in an identifiers list
# under a principals block whose type is "AWS" or "*". The statement effect is
# optional in this data source and defaults to Allow, so a missing effect
# counts as Allow.
ds_effect_allow(stmt) { not stmt.effect }
ds_effect_allow(stmt) { lower(stmt.effect) == "allow" }

ds_granted(document, pol) := {p |
    ds := document.data.aws_iam_policy_document[policy_data_source_name(pol.policy)]
    stmt := terraLib.getArray(ds.statement)[_]
    ds_effect_allow(stmt)
    pr := terraLib.getArray(stmt.principals)[_]
    granting_principal_types[lower(pr.type)]
    p := terraLib.getArray(pr.identifiers)[_]
}

tf_granted_principals(document, bucket, name) := granted {
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    is_string(pol.policy)
    granted := json_granted(pol) | ds_granted(document, pol)
}

# --- Logic ---
# Fail when an Allow statement grants access to a principal outside the set.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    unauth := tf_granted_principals(document, bucket, name) - authorized_principals
    count(unauth) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must only grant access to authorized principals: %v", [name, authorized_principals]),
        "keyActualValue": sprintf("bucket '%s' policy grants access to unauthorized principal(s): %v", [name, unauth]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# The data block a policy names: data.aws_iam_policy_document.<name>.json,
# written with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}
