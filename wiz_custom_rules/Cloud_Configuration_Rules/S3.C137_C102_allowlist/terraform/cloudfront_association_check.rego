package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized CloudFront distribution IDs (OAC) and origin access identity IDs (OAI).
# Keep in sync with the cloud matcher.
authorized_cloudfront_ids := {
    "E2AUTHORIZED12345",
}

# --- Policy statements ---
# A bucket policy is written as JSON (heredoc or jsonencode), or comes from an
# aws_iam_policy_document data source, which arrives resolved (Statements,
# Principals, condition values as lists) or as a reference to the data block
# in the same file. Each Allow statement is read into one shape:
# {"aws": [...], "canonical": [...], "service": [...], "conditions": [...]}.

json_doc(pol) := doc {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
    is_object(doc)
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    doc := json_doc(pol)
}

# A resolved data source statement may leave Effect out, which means Allow.
json_effect_allow(stmt) { not stmt.Effect }
json_effect_allow(stmt) { stmt.Effect == "Allow" }

json_principal_object(stmt) := stmt.Principal { is_object(stmt.Principal) }
json_principal_object(stmt) := stmt.Principals { is_object(stmt.Principals) }

json_principals(stmt, kind) := [v |
    values := json_principal_object(stmt)[k]
    lower(k) == kind
    v := terraLib.getArray(values)[_]
]

json_conditions(stmt) := [{"operator": operator, "key": lower(key), "values": terraLib.getArray(v)} |
    v := stmt.Condition[operator][key]
]

# The data block a policy names: data.aws_iam_policy_document.<name>.json.
policy_data_source(pol) := m[1] {
    is_string(pol.policy)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json\s*\}?\s*$`, pol.policy, 1)[0]
}

# effect is optional in a data block and defaults to Allow.
hcl_effect_allow(stmt) { not stmt.effect }
hcl_effect_allow(stmt) { lower(stmt.effect) == "allow" }

hcl_principals(stmt, kind) := [v |
    pr := terraLib.getArray(object.get(stmt, "principals", []))[_]
    lower(pr.type) == kind
    v := terraLib.getArray(pr.identifiers)[_]
]

hcl_conditions(stmt) := [{"operator": c.test, "key": lower(c.variable), "values": terraLib.getArray(c.values)} |
    c := terraLib.getArray(object.get(stmt, "condition", []))[_]
]

allow_statements(document, pol) := json_allows | hcl_allows {
    json_allows := {s |
        stmt := json_statements(pol)[_]
        json_effect_allow(stmt)
        s := {
            "aws": json_principals(stmt, "aws"),
            "canonical": json_principals(stmt, "canonicaluser"),
            "service": json_principals(stmt, "service"),
            "conditions": json_conditions(stmt),
        }
    }
    hcl_allows := {s |
        ds := document.data.aws_iam_policy_document[policy_data_source(pol)]
        stmt := terraLib.getArray(ds.statement)[_]
        hcl_effect_allow(stmt)
        s := {
            "aws": hcl_principals(stmt, "aws"),
            "canonical": hcl_principals(stmt, "canonicaluser"),
            "service": hcl_principals(stmt, "service"),
            "conditions": hcl_conditions(stmt),
        }
    }
}

# --- CloudFront associations ---
# Legacy OAI association: the principal is an identity of the "cloudfront"
# account, written "arn:aws:iam::cloudfront:user/CloudFront Origin Access
# Identity <ID>", or a reference to an identity this configuration creates.
oai_reference(v) {
    is_string(v)
    regex.match(`aws_cloudfront_origin_access_identity\.`, v)
}

tf_is_oai_principal(v) {
    parts := tocm_arn_parts(v)
    parts.service == "iam"
    parts.account == "cloudfront"
}

tf_is_oai_principal(v) { oai_reference(v) }

# The ID of an identity created in the same configuration is not resolved by
# this source scan, so it is never approved.
tf_oai_approved(v) {
    not tocm_tf_unresolved(v)
    not oai_reference(v)
    tocm_arn_parts(v).resource == sprintf("user/CloudFront Origin Access Identity %s", [authorized_cloudfront_ids[_]])
}

# Modern OAC association: the cloudfront.amazonaws.com service principal,
# limited to a distribution by aws:SourceArn.
is_oac(stmt) { lower(stmt.service[_]) == "cloudfront.amazonaws.com" }

# Only these operators limit the grant to the listed values.
source_arn_operators := {"StringEquals", "StringEqualsIfExists", "ArnEquals", "ArnEqualsIfExists", "ArnLike", "ArnLikeIfExists"}

tf_source_arn_tests(stmt) := [c.values |
    c := stmt.conditions[_]
    source_arn_operators[c.operator]
    c.key == "aws:sourcearn"
]

# A value is approved when it is the ARN of an approved distribution, with no
# wildcard in it. A reference to a distribution is not resolved by this source
# scan.
tf_distribution_approved(v) {
    not tocm_tf_unresolved(v)
    not regex.match(`[*?]`, v)
    parts := tocm_arn_parts(v)
    parts.service == "cloudfront"
    parts.region == ""
    parts.resource == sprintf("distribution/%s", [authorized_cloudfront_ids[_]])
}

tf_unapproved_values(values) := [v | v := values[_]; not tf_distribution_approved(v)]

# One test must hold approved distributions only; the values of a test are
# alternatives, so one that is not approved opens the grant to it.
tf_oac_authorized(stmt) {
    values := tf_source_arn_tests(stmt)[_]
    count(values) > 0
    count(tf_unapproved_values(values)) == 0
}

tf_unapproved_associations(document, bucket, name) := {msg |
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    stmt := allow_statements(document, pol)[_]
    msg := statement_issues(stmt)[_]
}

# A value as it is shown in a finding.
shown(v) := sprintf("'%v', which is not resolved by this source scan", [v]) {
    unresolved_in_source(v)
} else := sprintf("'%v'", [v])

unresolved_in_source(v) { tocm_tf_unresolved(v) }
unresolved_in_source(v) { is_string(v); regex.match(`^(var|local|module|data|aws_[a-z0-9_]+)\.`, v) }

statement_issues(stmt) := oai | canonical | oac_values | oac_untested {
    oai := {sprintf("origin access identity %s", [shown(v)]) |
        v := stmt.aws[_]
        tf_is_oai_principal(v)
        not tf_oai_approved(v)
    }
    canonical := {sprintf("origin access identity %s", [shown(v)]) |
        v := stmt.canonical[_]
        oai_reference(v)
    }
    oac_values := {sprintf("aws:SourceArn %s", [shown(v)]) |
        is_oac(stmt)
        not tf_oac_authorized(stmt)
        v := tf_unapproved_values(tf_source_arn_tests(stmt)[_])[_]
    }
    oac_untested := {"the CloudFront service with no aws:SourceArn test that uses StringEquals, ArnEquals or ArnLike" |
        is_oac(stmt)
        count(tf_source_arn_tests(stmt)) == 0
    }
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    issues := tf_unapproved_associations(document, bucket, name)
    count(issues) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must grant CloudFront access only to authorized IDs, as an origin access identity principal or as the cloudfront.amazonaws.com service limited by aws:SourceArn (StringEquals, ArnEquals or ArnLike, no wildcard): %v", [name, authorized_cloudfront_ids]),
        "keyActualValue": sprintf("bucket '%s' policy grants CloudFront access that is not approved: %s", [name, concat("; ", sort(issues))]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# --- Matching helpers ---
# --- toc-match begin: arn v1 ---
# Parts of an AWS ARN; the resource keeps any further ":" characters.
tocm_arn_parts(arn) := {"partition": s[1], "service": s[2], "region": s[3], "account": s[4], "resource": r} {
    is_string(arn)
    s := split(trim_space(arn), ":")
    count(s) >= 6
    s[0] == "arn"
    s[1] != ""
    s[2] != ""
    r := concat(":", array.slice(s, 5, count(s)))
    r != ""
}

tocm_arn_equal(a, b) {
    tocm_arn_parts(a) == tocm_arn_parts(b)
}

tocm_arn_allowed(arn, allowed) {
    tocm_arn_equal(arn, allowed[_])
}

# Bucket name of an S3 bucket or object ARN (arn:aws:s3:::bucket[/key]).
tocm_s3_arn_bucket(arn) := b {
    p := tocm_arn_parts(arn)
    p.service == "s3"
    p.region == ""
    p.account == ""
    b := split(p.resource, "/")[0]
    b != ""
}
# --- toc-match end: arn v1 ---

# --- toc-match begin: tf v1 ---
# A Terraform value that is still an unresolved reference ("${...}"). Treat
# it as unknown: never compare it with an allowlist as a string.
tocm_tf_unresolved(v) {
    is_string(v)
    contains(v, "${")
}
# --- toc-match end: tf v1 ---
