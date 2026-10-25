package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized CloudFront distribution IDs (OAC) and origin access identity IDs (OAI).
# Keep in sync with the cloud matcher.
authorized_cloudfront_ids := {
    "E2AUTHORIZED12345",
}

# --- Policy helpers ---
principal_aws(stmt) := {v | v := stmt.Principal.AWS; is_string(v)} {
    is_string(stmt.Principal.AWS)
} else := {v | v := stmt.Principal.AWS[_]}

condition_values(v) := {v} { is_string(v) }
condition_values(v) := {x | x := v[_]} { is_array(v) }

source_arns(stmt) := arns {
    arns := {a |
        conditions := stmt.Condition[operator]
        contains(lower(operator), "equals")
        val := conditions[key]
        lower(key) == "aws:sourcearn"
        a := condition_values(val)[_]
    } | {a |
        conditions := stmt.Condition[operator]
        contains(lower(operator), "arnlike")
        val := conditions[key]
        lower(key) == "aws:sourcearn"
        a := condition_values(val)[_]
    }
}

id_authorized(ref) {
    id := authorized_cloudfront_ids[_]
    contains(ref, id)
}

# A legacy OAI association that references an unauthorized identity.
unauthorized_oai(stmt) {
    stmt.Effect == "Allow"
    p := principal_aws(stmt)[_]
    contains(lower(p), "cloudfront")
    not id_authorized(p)
}

# A modern OAC association (cloudfront.amazonaws.com service principal) whose
# aws:SourceArn does not reference an authorized distribution.
is_oac(stmt) {
    stmt.Effect == "Allow"
    stmt.Principal.Service == "cloudfront.amazonaws.com"
}

is_oac(stmt) {
    stmt.Effect == "Allow"
    stmt.Principal.Service[_] == "cloudfront.amazonaws.com"
}

unauthorized_oac(stmt) {
    is_oac(stmt)
    not tf_oac_authorized(stmt)
}

tf_oac_authorized(stmt) {
    a := source_arns(stmt)[_]
    id_authorized(a)
}

tf_has_unauthorized_association(document, bucket, name) {
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
    stmt := terraLib.getStatement(doc)[_]
    unauthorized_oai(stmt)
}

tf_has_unauthorized_association(document, bucket, name) {
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
    stmt := terraLib.getStatement(doc)[_]
    unauthorized_oac(stmt)
}

# --- Data-source (aws_iam_policy_document) form ---
# effect is optional here and defaults to Allow.
ds_effect_allow(stmt) { not stmt.effect }
ds_effect_allow(stmt) { lower(stmt.effect) == "allow" }

ds_arn_operator(t) { contains(lower(t), "equals") }
ds_arn_operator(t) { contains(lower(t), "arnlike") }

ds_oac_authorized(stmt) {
    c := terraLib.getArray(stmt.condition)[_]
    ds_arn_operator(c.test)
    lower(c.variable) == "aws:sourcearn"
    a := condition_values(c.values)[_]
    id_authorized(a)
}

# Legacy OAI association to an unauthorized identity.
tf_has_unauthorized_association(document, bucket, name) {
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    is_string(pol.policy)
    ds := document.data.aws_iam_policy_document[dsName]
    contains(pol.policy, dsName)
    stmt := terraLib.getArray(ds.statement)[_]
    ds_effect_allow(stmt)
    pr := terraLib.getArray(stmt.principals)[_]
    lower(pr.type) == "aws"
    ident := terraLib.getArray(pr.identifiers)[_]
    contains(lower(ident), "cloudfront")
    not id_authorized(ident)
}

# Modern OAC association whose aws:SourceArn is not an authorized distribution.
tf_has_unauthorized_association(document, bucket, name) {
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    is_string(pol.policy)
    ds := document.data.aws_iam_policy_document[dsName]
    contains(pol.policy, dsName)
    stmt := terraLib.getArray(ds.statement)[_]
    ds_effect_allow(stmt)
    pr := terraLib.getArray(stmt.principals)[_]
    lower(pr.type) == "service"
    terraLib.getArray(pr.identifiers)[_] == "cloudfront.amazonaws.com"
    not ds_oac_authorized(stmt)
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    tf_has_unauthorized_association(document, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must grant CloudFront access only to authorized IDs: %v", [name, authorized_cloudfront_ids]),
        "keyActualValue": sprintf("bucket '%s' policy grants CloudFront access to an unauthorized distribution or identity", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
