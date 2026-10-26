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

# IAM principals granted access by Allow statements in the bucket policy JSON.
json_granted(pol) := granted {
    granted := {p |
        doc := json.unmarshal(pol.policy)
        stmt := terraLib.getStatement(doc)[_]
        stmt.Effect == "Allow"
        p := principal_values(stmt.Principal.AWS)[_]
    } | {p |
        doc := json.unmarshal(pol.policy)
        stmt := terraLib.getStatement(doc)[_]
        stmt.Effect == "Allow"
        stmt.Principal == "*"
        p := "*"
    }
}

# From a policy-document data source: principals live in an identifiers list
# under a principals block whose type is "AWS". The statement effect is
# optional in this data source and defaults to Allow, so a missing effect
# counts as Allow.
ds_effect_allow(stmt) { not stmt.effect }
ds_effect_allow(stmt) { lower(stmt.effect) == "allow" }

ds_granted(document, pol) := {p |
    ds := document.data.aws_iam_policy_document[dsName]
    contains(pol.policy, dsName)
    stmt := terraLib.getArray(ds.statement)[_]
    ds_effect_allow(stmt)
    pr := terraLib.getArray(stmt.principals)[_]
    lower(pr.type) == "aws"
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
