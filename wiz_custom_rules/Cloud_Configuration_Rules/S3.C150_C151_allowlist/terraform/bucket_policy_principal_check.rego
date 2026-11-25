package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_principals := {
    "arn:aws:iam::123456789012:role/authorized-role",
    "arn:aws:iam::123456789012:root",
}

# Canonical user IDs that Allow statements may grant access to, written as
# the policy writes them. Empty means no canonical user may be granted
# access; add an ID once approved. IDs compare in lower case.
authorized_canonical_users := set()

# --- Policy helpers ---
principal_values(v) := {v} { is_string(v) }
principal_values(v) := {x | x := v[_]} { is_array(v) }

# Principal types that name IAM principals: "AWS", and "*" for everyone.
granting_principal_types := {"aws", "*"}

# A resolved data source arrives with Statements and Principals
# ({"<type>": [identifiers]}), and with no Effect when it defaults to Allow.
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

json_granted(pol) := {p |
    stmt := json_statements(pol)[_]
    json_effect_allow(stmt)
    p := json_principals(stmt)[_]
}

# Canonical users, as {"CanonicalUser": ...} or, resolved, under Principals.
json_canonical_users(stmt) := direct | resolved {
    direct := {id | id := principal_values(stmt.Principal.CanonicalUser)[_]}
    resolved := {id |
        v := stmt.Principals[t]
        lower(t) == "canonicaluser"
        id := principal_values(v)[_]
    }
}

json_granted_canonical(pol) := {id |
    stmt := json_statements(pol)[_]
    json_effect_allow(stmt)
    id := json_canonical_users(stmt)[_]
}

# A data source statement with no effect defaults to Allow.
ds_effect_allow(stmt) { not stmt.effect }
ds_effect_allow(stmt) { lower(stmt.effect) == "allow" }

# Written statements of data block ds, including those an override may replace.
ds_statements(ds) := terraLib.getArray(object.get(ds, "statement", []))

ds_granted(ds) := {p |
    stmt := ds_statements(ds)[_]
    ds_effect_allow(stmt)
    pr := terraLib.getArray(stmt.principals)[_]
    granting_principal_types[lower(pr.type)]
    p := terraLib.getArray(pr.identifiers)[_]
}

ds_granted_canonical(ds) := {id |
    stmt := ds_statements(ds)[_]
    ds_effect_allow(stmt)
    pr := terraLib.getArray(stmt.principals)[_]
    lower(pr.type) == "canonicaluser"
    id := terraLib.getArray(pr.identifiers)[_]
}

# The policy argument and every linked aws_s3_bucket_policy, read the same way.
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
source_documents(src) := tf_documents_or_none(src.doc, src.pol.policy)

tf_granted_principals(i, bucket, name) := {p |
    src := bucket_policies(i, bucket, name)[_]
    is_string(src.pol.policy)
    granted := json_granted(src.pol) | ds_granted(source_documents(src)[_])
    p := granted[_]
}

tf_granted_canonical(i, bucket, name) := {id |
    src := bucket_policies(i, bucket, name)[_]
    is_string(src.pol.policy)
    granted := json_granted_canonical(src.pol) | ds_granted_canonical(source_documents(src)[_])
    id := granted[_]
}

# --- NotPrincipal ---
# An Allow with NotPrincipal grants everyone it does not list, so it fails. A
# resolved not_principals statement has no principal, so that fails too.
tf_set_value(v) {
    v != null
    v != []
    v != {}
    v != ""
}

tf_json_principal_keys := {"Principal", "Principals", "NotPrincipal", "NotPrincipals"}

json_not_principal_issue(stmt) := "an Allow statement written with NotPrincipal, which grants every principal except those it lists" {
    tf_set_value(object.get(stmt, "NotPrincipal", null))
} else := "an Allow statement written with NotPrincipal, which grants every principal except those it lists" {
    tf_set_value(object.get(stmt, "NotPrincipals", null))
} else := "an Allow statement that names no principal, as a statement written with not_principals reads once its data source is resolved" {
    count([k | k := tf_json_principal_keys[_]; tf_set_value(object.get(stmt, k, null))]) == 0
}

json_not_principal_issues(pol) := {msg |
    stmt := json_statements(pol)[_]
    json_effect_allow(stmt)
    msg := json_not_principal_issue(stmt)
}

ds_not_principal_issue(stmt) := "an Allow statement written with not_principals, which grants every principal except those it lists" {
    tf_set_value(object.get(stmt, "not_principals", null))
} else := "an Allow statement that names no principal" {
    not tf_set_value(object.get(stmt, "principals", null))
    not tf_statement_dynamic_principals(stmt)
}

ds_not_principal_issues(ds) := {msg |
    stmt := ds_statements(ds)[_]
    ds_effect_allow(stmt)
    msg := ds_not_principal_issue(stmt)
}

tf_not_principal_issues(i, bucket, name) := {msg |
    src := bucket_policies(i, bucket, name)[_]
    is_string(src.pol.policy)
    issues := json_not_principal_issues(src.pol) | ds_not_principal_issues(source_documents(src)[_])
    msg := issues[_]
}

# --- Statements the source does not show ---
# Statements from a dynamic block or other documents may grant any principal.
ds_unshown_issues(n, ds) := documents | statements {
    documents := {sprintf("statements that data.aws_iam_policy_document.%s takes from a dynamic statement block or from other policy documents, which the Terraform source does not show", [n]) |
        tf_document_unshown(ds)
    }
    statements := {sprintf("an Allow statement in data.aws_iam_policy_document.%s whose principals a dynamic block generates, which the Terraform source does not show", [n]) |
        stmt := ds_statements(ds)[_]
        ds_effect_allow(stmt)
        tf_statement_dynamic_principals(stmt)
    }
}

tf_unshown_issues(i, bucket, name) := documents | composed | unreadable {
    documents := {msg |
        src := bucket_policies(i, bucket, name)[_]
        n := policy_data_source_name(src.pol.policy)
        msg := ds_unshown_issues(n, source_documents(src)[_])[_]
    }
    # A policy matched to composed documents names them all and is not
    # reported again as unreadable.
    composed := {sprintf("statements that %s takes from other policy documents, which the scan drops before the rule runs", [sources]) |
        src := bucket_policies(i, bucket, name)[_]
        names := tf_resolved_composed_from(src.doc, src.pol.policy)
        count(names) > 0
        sources := concat(" or ", [sprintf("data.aws_iam_policy_document.%s", [n]) | n := sort(names)[_]])
    }
    unreadable := {sprintf("content the scan cannot read: %s", [tf_policy_unreadable_reason(v)]) |
        src := bucket_policies(i, bucket, name)[_]
        v := src.pol.policy
        not tf_policy_readable(src.doc, v)
        count(tf_resolved_composed_from(src.doc, v)) == 0
    }
}

authorized_canonical_lower := {lower(trim_space(id)) | id := authorized_canonical_users[_]}

tf_unauthorized(i, bucket, name) := principals | canonical {
    principals := tf_granted_principals(i, bucket, name) - authorized_principals
    canonical := {sprintf("CanonicalUser:%s", [id]) |
        id := tf_granted_canonical(i, bucket, name)[_]
        not canonical_authorized(id)
    }
}

canonical_authorized(id) {
    is_string(id)
    count({lower(trim_space(id))} & authorized_canonical_lower) > 0
}

# --- Logic ---
# Fail on an unauthorized grant, a NotPrincipal Allow, or unshown statements.
tf_findings(i, bucket, name) := array.concat(
    [msg |
        unauth := tf_unauthorized(i, bucket, name)
        count(unauth) > 0
        msg := sprintf("bucket '%s' policy grants access to unauthorized principal(s): %v", [name, unauth])
    ],
    [msg |
        issue := sort(tf_not_principal_issues(i, bucket, name) | tf_unshown_issues(i, bucket, name))[_]
        msg := sprintf("bucket '%s' policy has %s, so it cannot be shown to stay within the authorized principals", [name, issue])
    ],
)

WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    findings := tf_findings(i, bucket, name)
    count(findings) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy (policy argument or aws_s3_bucket_policy) must only grant access to authorized principals: %v, and authorized canonical users: %v, each named as a principal; an Allow written with NotPrincipal is reported", [name, authorized_principals, authorized_canonical_users]),
        "keyActualValue": concat("; ", findings),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# The <name> of data.aws_iam_policy_document.<name>.json, with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}

# A policy naming no data block this scan holds is read from its JSON alone.
tf_documents_or_none(i, v) := docs {
    docs := [c.block | c := tf_lookup(i, "data", "aws_iam_policy_document", policy_data_source_name(v))[_]]
    count(docs) > 0
} else := [{}]

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
