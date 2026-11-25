package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Authorized CloudFront distribution IDs (OAC) and origin access identity IDs (OAI).
# Keep in sync with the cloud matcher.
authorized_cloudfront_ids := {
    "E2AUTHORIZED12345",
}

# --- Policy statements ---
# A policy is JSON, a resolved data source (plural keys) or a data block
# reference. Each Allow is read into {aws, canonical, service, conditions}.

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

# The data block a policy names, as data.aws_iam_policy_document.<name>.json.
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}

# A policy naming no data block this scan holds is read from its JSON alone.
tf_documents_or_none(i, v) := docs {
    docs := [c.block | c := tf_lookup(i, "data", "aws_iam_policy_document", policy_data_source_name(v))[_]]
    count(docs) > 0
} else := [{}]

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

# Allows in the policy's JSON and in data block ds ({} when it names none),
# including statements an override document may replace.
allow_statements(ds, pol) := json_allows | hcl_allows {
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
        stmt := terraLib.getArray(object.get(ds, "statement", []))[_]
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
# Legacy OAI: an AWS principal of the "cloudfront" account, or a reference to
# an identity this configuration creates.
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

# A created identity's ID is unknown here, so it is never approved.
tf_oai_approved(v) {
    not tocm_tf_unresolved(v)
    not oai_reference(v)
    tocm_arn_parts(v).resource == sprintf("user/CloudFront Origin Access Identity %s", [authorized_cloudfront_ids[_]])
}

# OAC: the cloudfront.amazonaws.com service, limited by aws:SourceArn.
is_oac(stmt) { lower(stmt.service[_]) == "cloudfront.amazonaws.com" }

# Only these operators limit the grant to the listed values.
source_arn_operators := {"StringEquals", "StringEqualsIfExists", "ArnEquals", "ArnEqualsIfExists", "ArnLike", "ArnLikeIfExists"}

tf_source_arn_tests(stmt) := [c.values |
    c := stmt.conditions[_]
    source_arn_operators[c.operator]
    c.key == "aws:sourcearn"
]

# An approved distribution ARN with no wildcard; a reference is never approved.
tf_distribution_approved(v) {
    not tocm_tf_unresolved(v)
    not regex.match(`[*?]`, v)
    parts := tocm_arn_parts(v)
    parts.service == "cloudfront"
    parts.region == ""
    parts.resource == sprintf("distribution/%s", [authorized_cloudfront_ids[_]])
}

tf_unapproved_values(values) := [v | v := values[_]; not tf_distribution_approved(v)]

# Values in a test are alternatives, so every one must be approved.
tf_oac_authorized(stmt) {
    values := tf_source_arn_tests(stmt)[_]
    count(values) > 0
    count(tf_unapproved_values(values)) == 0
}

# The bucket's policy argument and every linked aws_s3_bucket_policy.
bucket_policies(i, bucket, name) := inline | linked {
    inline := {src | is_string(object.get(bucket, "policy", null)); src := {"doc": i, "pol": bucket}}
    linked := {{"doc": j, "pol": pol} |
        pol := input.document[j].resource.aws_s3_bucket_policy[pName]
        not tf_not_created(pol)
        terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
        tf_reference_reaches(i, j, pol.bucket, "aws_s3_bucket", name)
    }
}

# A grant in any data block a source names is reported.
source_documents(src) := tf_documents_or_none(src.doc, object.get(src.pol, "policy", null))

# Unshown statements or dynamic Allow principals may grant CloudFront access.
unshown_issues(src) := documents | statements {
    n := policy_data_source_name(src.pol.policy)
    documents := {sprintf("statements that data.aws_iam_policy_document.%s takes from a dynamic statement block or from other policy documents, which the Terraform source does not show and which may grant CloudFront access", [n]) |
        tf_document_unshown(source_documents(src)[_])
    }
    statements := {sprintf("an Allow statement in data.aws_iam_policy_document.%s whose principals a dynamic block generates, which the Terraform source does not show and which may name CloudFront", [n]) |
        stmt := terraLib.getArray(object.get(source_documents(src)[_], "statement", []))[_]
        hcl_effect_allow(stmt)
        tf_statement_dynamic_principals(stmt)
    }
}

tf_unapproved_associations(i, bucket, name) := granted | unshown {
    granted := {msg |
        src := bucket_policies(i, bucket, name)[_]
        stmt := allow_statements(source_documents(src)[_], src.pol)[_]
        msg := statement_issues(stmt)[_]
    }
    unshown := {msg |
        src := bucket_policies(i, bucket, name)[_]
        msg := unshown_issues(src)[_]
    } | composed_issues(i, bucket, name) | {sprintf("content the scan cannot read, which may grant CloudFront access: %s", [tf_policy_unreadable_reason(v)]) |
        src := bucket_policies(i, bucket, name)[_]
        v := src.pol.policy
        not tf_policy_readable(src.doc, v)
        count(tf_resolved_composed_from(src.doc, v)) == 0
    }
}

# Names every matching composed document: the scan cannot tell them apart.
composed_issues(i, bucket, name) := {sprintf("statements that %s takes from other policy documents, which the scan drops before the rule runs and which may grant CloudFront access", [sources]) |
    src := bucket_policies(i, bucket, name)[_]
    names := tf_resolved_composed_from(src.doc, src.pol.policy)
    count(names) > 0
    sources := concat(" or ", [sprintf("data.aws_iam_policy_document.%s", [n]) | n := sort(names)[_]])
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
    not tf_not_created(bucket)
    issues := tf_unapproved_associations(i, bucket, name)
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

# --- tf_policy_readable: begin ---
# A policy shows its statements when it is JSON with a Statement element or
# names an aws_iam_policy_document the scan holds.
tf_policy_statement_keys := {"Statement", "Statements"}

tf_policy_json_readable(v) {
    is_string(v)
    doc := json.unmarshal(v)
    is_object(doc)
    k := tf_policy_statement_keys[_]
    object.get(doc, k, null) != null
}

tf_policy_readable(i, v) { tf_policy_json_readable(v) }

tf_policy_readable(i, v) {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
    count(tf_lookup(i, "data", "aws_iam_policy_document", m[1])) > 0
}

# Why a policy value does not show its statements.
tf_policy_unreadable_reason(v) := "the policy value is empty, as a scan gives a policy document data source it cannot resolve, such as one with a dynamic block" {
    v == ""
} else := sprintf("the policy value %v does not show its statements in the Terraform source", [v])
# --- tf_policy_readable: end ---

# --- tf_scan_lookup: begin ---
# A reference reads the definition in its own file, else every definition in
# the other files of its module: the document id up to its last "/" or "\".
tf_module(i) := m[1] {
    m := regex.find_all_string_submatch_n(`^(.*)[/\\][^/\\]*$`, input.document[i].id, 1)[0]
} else := ""

# Documents whose <kind>.<rtype>.<name> a reference in document i reads.
tf_lookup_docs(i, kind, rtype, name) := {i} {
    input.document[i][kind][rtype][name]
} else := {j |
    input.document[j][kind][rtype][name]
    j != i
    tf_module(j) == tf_module(i)
}

# Those definitions, as {"doc": index, "block": definition}.
tf_lookup(i, kind, rtype, name) := {{"doc": j, "block": input.document[j][kind][rtype][name]} |
    j := tf_lookup_docs(i, kind, rtype, name)[_]
}

# A value naming <rtype>.<name> by its address, with any instance index.
tf_names_address(v, rtype, name) {
    is_string(v)
    regex.match(sprintf(`(^|[^A-Za-z0-9_.-])%s\.%s(\[[^\]]*\])?\.`, [rtype, name]), v)
}

# A reference v in document j reaches <rtype>.<name> of document i.
tf_reference_reaches(i, j, v, rtype, name) {
    j == i
}

tf_reference_reaches(i, j, v, rtype, name) {
    j != i
    tf_names_address(v, rtype, name)
    tf_lookup_docs(j, "resource", rtype, name)[i]
}
# --- tf_scan_lookup: end ---

# --- tf_never_created: begin ---
# A resource with a literal count of 0 or an empty for_each is never created
# and is not judged; any other expression is judged.
tf_expression(v) := trim_space(trim_suffix(trim_prefix(trim_space(v), "${"), "}")) {
    is_string(v)
}

tf_empty_collection := `^(\[\s*\]|\{\s*\}|toset\(\s*(\[\s*\]|\{\s*\})\s*\))$`

tf_zero(v) {
    v == 0
}

tf_zero(v) {
    tf_expression(v) == "0"
}

tf_empty(v) {
    is_array(v)
    count(v) == 0
}

tf_empty(v) {
    is_object(v)
    count(v) == 0
}

tf_empty(v) {
    regex.match(tf_empty_collection, tf_expression(v))
}

tf_not_created(r) {
    tf_zero(object.get(r, "count", null))
}

tf_not_created(r) {
    tf_empty(object.get(r, "for_each", null))
}
# --- tf_never_created: end ---

# --- tf_dynamic: begin ---
# A dynamic block generates blocks the source does not show; one whose
# for_each is a literal empty collection generates nothing. Needs
# tf_never_created.
tf_dynamic_blocks(b, label) := {d |
    d := terraLib.getArray(b.dynamic[_][label])[_]
    is_object(d)
} | {d |
    d := terraLib.getArray(b.dynamic[label])[_]
    is_object(d)
}

tf_dynamic(b, label) {
    d := tf_dynamic_blocks(b, label)[_]
    not tf_empty(object.get(d, "for_each", null))
}
# --- tf_dynamic: end ---

# --- tf_policy_document: begin ---
# Statements a policy document does not show: a dynamic statement block, and
# source or override documents. Needs tf_dynamic.
tf_document_set(v) {
    v != null
    v != []
    v != {}
    v != ""
}

tf_document_overridden(ds) {
    tf_document_set(object.get(ds, {"override_policy_documents", "override_json"}[_], null))
}

# The document may hold statements beyond the ones it writes out.
tf_document_unshown(ds) {
    tf_dynamic(ds, "statement")
}

tf_document_unshown(ds) {
    tf_document_set(object.get(ds, {"source_policy_documents", "source_json"}[_], null))
}

tf_document_unshown(ds) {
    tf_document_overridden(ds)
}

# A written statement whose principals a dynamic block generates.
tf_statement_dynamic_principals(stmt) {
    tf_dynamic(stmt, {"principals", "not_principals"}[_])
}

tf_statement_dynamic(stmt) {
    tf_dynamic(stmt, {"condition", "principals", "not_principals"}[_])
}

# Written statements that can prove a Deny: none when an override document
# may replace them, and none with a dynamic block inside.
tf_deny_statements(ds) := [stmt |
    not tf_document_overridden(ds)
    stmt := terraLib.getArray(object.get(ds, "statement", []))[_]
    not tf_statement_dynamic(stmt)
]
# --- tf_policy_document: end ---

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

# --- tf_resolved_composition: begin ---
# A scan resolves a policy document and drops its source and override
# statements. The resolved policy is matched back to its module's documents
# by its statements, and blamed on composed ones only when no plain document
# matches. Needs tf_policy_document and tf_scan_lookup.
tf_resolved_list(v) := v {
    is_array(v)
} else := [v] {
    is_string(v)
} else := []

# A value as a resolved document writes it: a reference without "${}".
tf_resolved_bare(v) := regex.replace(v, `\$\{([^${}]+)\}`, "$1") {
    is_string(v)
} else := v

tf_resolved_values(v) := sort({tf_resolved_bare(x) | x := tf_resolved_list(v)[_]})

tf_resolved_actions(v) := sort({lower(tf_resolved_bare(a)) | a := tf_resolved_list(v)[_]; is_string(a)})

# Principals as sorted [type, identifier] pairs.
tf_resolved_principals(p) := sort({[t, x] | ids := p[t]; x := tf_resolved_values(ids)[_]}) {
    is_object(p)
} else := []

tf_written_principals(blocks) := sort({[b.type, x] | b := terraLib.getArray(blocks)[_]; x := tf_resolved_values(b.identifiers)[_]})

# Conditions as sorted [test, variable, values]; blocks sharing a test and
# variable combine their values, as the scan does.
tf_resolved_conditions(c) := sort({[t, k, tf_resolved_values(vals)] | vals := c[t][k]}) {
    is_object(c)
} else := []

tf_written_conditions(blocks) := sort({[t, k, sort({x | b := terraLib.getArray(blocks)[_]; b.test == t; b.variable == k; x := tf_resolved_values(b.values)[_]})] |
    c := terraLib.getArray(blocks)[_]
    t := c.test
    k := c.variable
})

# A statement in full, resolved and as written, so the two compare.
tf_resolved_key(s) := [
    object.get(s, "Sid", ""),
    lower(object.get(s, "Effect", "Allow")),
    tf_resolved_actions(object.get(s, "Actions", [])),
    tf_resolved_actions(object.get(s, "Not_actions", [])),
    tf_resolved_values(object.get(s, "Resources", [])),
    tf_resolved_values(object.get(s, "Not_resources", [])),
    tf_resolved_principals(object.get(s, "Principals", {})),
    tf_resolved_principals(object.get(s, "Not_principals", {})),
    tf_resolved_conditions(object.get(s, "Condition", {})),
]

tf_written_key(s) := [
    object.get(s, "sid", ""),
    lower(object.get(s, "effect", "Allow")),
    tf_resolved_actions(object.get(s, "actions", [])),
    tf_resolved_actions(object.get(s, "not_actions", [])),
    tf_resolved_values(object.get(s, "resources", [])),
    tf_resolved_values(object.get(s, "not_resources", [])),
    tf_written_principals(object.get(s, "principals", [])),
    tf_written_principals(object.get(s, "not_principals", [])),
    tf_written_conditions(object.get(s, "condition", [])),
]

# JSON written by hand is never matched.
tf_hand_written_keys := {"Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal"}

# A document with any dynamic block resolves to an empty string.
tf_resolves_to_json(ds) {
    not ds.dynamic
    count([s | s := terraLib.getArray(object.get(ds, "statement", []))[_]; s.dynamic]) == 0
}

tf_composed_document(ds) {
    tf_document_set(object.get(ds, {"source_policy_documents", "override_policy_documents", "source_json", "override_json"}[_], null))
}

# The statements of a resolved policy string v; undefined for anything else.
tf_resolved_statements(v) := stmts {
    is_string(v)
    doc := json.unmarshal(v)
    is_object(doc)
    stmts := array.concat(terraLib.getArray(object.get(doc, "Statement", [])), terraLib.getArray(object.get(doc, "Statements", [])))
    count([s | s := stmts[_]; tf_hand_written_keys[k]; object.get(s, k, null) != null]) == 0
}

# Documents of i's module, as [name, index], whose statements match v.
tf_resolved_matches(i, v) := {[n, j] |
    stmts := tf_resolved_statements(v)
    ds := input.document[j].data.aws_iam_policy_document[n]
    tf_module(j) == tf_module(i)
    tf_resolves_to_json(ds)
    written := terraLib.getArray(object.get(ds, "statement", []))
    count(stmts) == count(written)
    {tf_resolved_key(s) | s := stmts[_]} == {tf_written_key(s) | s := written[_]}
}

# Composed documents v came from, when every document matching v is composed.
tf_resolved_composed_from(i, v) := {m[0] |
    matches := tf_resolved_matches(i, v)
    count([x | x := matches[_]; not tf_composed_document(input.document[x[1]].data.aws_iam_policy_document[x[0]])]) == 0
    m := matches[_]
}
# --- tf_resolved_composition: end ---
