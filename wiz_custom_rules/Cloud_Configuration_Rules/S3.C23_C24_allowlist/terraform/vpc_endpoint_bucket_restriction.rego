package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_buckets := {
    "arn:aws:s3:::authorized-bucket",
}

# --- Policy helpers ---
# A policy is IAM JSON, resolved data-source JSON (Actions, Resources) or a
# reference to an aws_iam_policy_document, on the endpoint or its policy.
is_s3_service(sn) { endswith(sn, ".s3") }

# The endpoint's own policy and each linked aws_vpc_endpoint_policy.
endpoint_policies(i, ep, name) := inline | assoc {
    inline := {src | is_string(ep.policy); src := {"doc": i, "policy": ep.policy}}
    assoc := {{"doc": j, "policy": p.policy} |
        p := input.document[j].resource.aws_vpc_endpoint_policy[pn]
        not tf_not_created(p)
        terraLib.associatedResources(p, ep, pn, name, "vpc_endpoint_id", "id")
        tf_reference_reaches(i, j, p.vpc_endpoint_id, "aws_vpc_endpoint", name)
        is_string(p.policy)
    }
}

ep_json_statements(policy) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    doc := json.unmarshal(policy)
}

# The data blocks a policy names, as {"doc": index, "block": definition}.
ep_documents(src) := tf_lookup(src.doc, "data", "aws_iam_policy_document", policy_data_source_name(src.policy))

# Every statement of the endpoint's policies, tagged with its shape and file.
ep_statements(i, ep, name) := json_stmts | hcl_stmts {
    sources := endpoint_policies(i, ep, name)
    json_stmts := {{"shape": "json", "stmt": stmt, "doc": src.doc} |
        src := sources[_]
        stmt := ep_json_statements(src.policy)[_]
    }
    hcl_stmts := {{"shape": "hcl", "stmt": stmt, "doc": c.doc} |
        src := sources[_]
        c := ep_documents(src)[_]
        stmt := terraLib.getArray(object.get(c.block, "statement", []))[_]
    }
}

ep_list(v) := v { is_array(v) } else := [v]

# effect defaults to Allow; a resolved data source omits Effect when unset.
ep_effect(s) := lower(object.get(s.stmt, "Effect", "Allow")) { s.shape == "json" }
ep_effect(s) := lower(object.get(s.stmt, "effect", "Allow")) { s.shape == "hcl" }

ep_resources(s) := array.concat(ep_list(object.get(s.stmt, "Resource", [])), ep_list(object.get(s.stmt, "Resources", []))) { s.shape == "json" }
ep_resources(s) := ep_list(object.get(s.stmt, "resources", [])) { s.shape == "hcl" }

has_any_policy(i, ep, name) {
    count(endpoint_policies(i, ep, name)) > 0
}

ep_allows(i, ep, name) := {s |
    s := ep_statements(i, ep, name)[_]
    ep_effect(s) == "allow"
}

# An Allow may name an authorized bucket or its objects. The bucket name is
# literal or stated by a module bucket, with no wildcard.
resource_authorized(res) {
    bucket := tocm_s3_arn_bucket(res)
    not regex.match(`[*?]`, bucket)
    p := tocm_arn_parts(res)
    tocm_arn_allowed(sprintf("arn:%s:s3:::%s", [p.partition, bucket]), authorized_buckets)
}

# A module bucket's id, bucket or arn, interpolated or bare. A bare address is
# never a literal bucket name, which cannot hold "_".
tf_bucket_reference_pattern := `(\$\{\s*)?(data\.)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(id|bucket|arn)(\s*\})?`

tf_balanced(m) {
    m[1] == ""
    m[5] == ""
}

tf_balanced(m) {
    m[1] != ""
    m[5] != ""
}

# The definitions a reference in document j names.
tf_referenced_buckets(j, ref) := [c.block | c := tf_lookup(j, "resource", "aws_s3_bucket", ref.name)[_]] { ref.block == "" }
tf_referenced_buckets(j, ref) := [c.block | c := tf_lookup(j, "data", "aws_s3_bucket", ref.name)[_]] { ref.block == "data." }

# A bucket created more than once has no single name.
tf_repeated(b) { object.get(b, "count", null) != null }
tf_repeated(b) { object.get(b, "for_each", null) != null }

# A literal bucket name; a generated or interpolated name is not known.
tf_stated_bucket_name(b) := n {
    not tf_repeated(b)
    n := b.bucket
    is_string(n)
    n != ""
    not contains(n, "${")
}

# Every definition a reference reads must state the same name.
tf_referenced_bucket_name(j, ref) := n {
    bs := tf_referenced_buckets(j, ref)
    count(bs) > 0
    names := [x | x := tf_stated_bucket_name(bs[_])]
    count(names) == count(bs)
    count({x | x := names[_]}) == 1
    n := names[0]
}

# The endpoint's partition, from its service name. An endpoint reaches only
# the buckets of its own partition.
tf_endpoint_region(ep) := m[1] {
    is_string(ep.service_name)
    m := regex.find_all_string_submatch_n(`^(?:cn\.)?com\.amazonaws\.([a-z0-9-]+)\.s3$`, ep.service_name, 1)[0]
}

tf_endpoint_partition(ep) := "aws-cn" {
    regex.match(`^cn-[a-z]+-[0-9]+$`, tf_endpoint_region(ep))
} else := "aws-us-gov" {
    regex.match(`^us-gov-[a-z]+-[0-9]+$`, tf_endpoint_region(ep))
} else := "aws" {
    regex.match(`^[a-z]{2}-[a-z]+-[0-9]+$`, tf_endpoint_region(ep))
}

# A reference's bucket name, or for arn its ARN in the endpoint's partition.
tf_reference_value(j, ep, ref) := tf_referenced_bucket_name(j, ref) {
    ref.attribute != "arn"
} else := sprintf("arn:%s:s3:::%s", [tf_endpoint_partition(ep), tf_referenced_bucket_name(j, ref)]) {
    ref.attribute == "arn"
}

# Resolves one bucket reference; any other interpolation leaves r unresolved.
tf_resolved_resource(j, ep, r) := c {
    ms := regex.find_all_string_submatch_n(tf_bucket_reference_pattern, r, -1)
    count(ms) == 1
    m := ms[0]
    tf_balanced(m)
    not contains(replace(r, m[0], ""), "${")
    ref := {"block": m[2], "name": m[3], "attribute": m[4]}
    c := replace(r, m[0], tf_reference_value(j, ep, ref))
}

tf_resource_authorized(j, ep, r) {
    resource_authorized(r)
}

tf_resource_authorized(j, ep, r) {
    resource_authorized(tf_resolved_resource(j, ep, r))
}

tf_unauthorized_resources(i, ep, name) := {r |
    s := ep_allows(i, ep, name)[_]
    r := ep_resources(s)[_]
    not tf_resource_authorized(s.doc, ep, r)
}

# An Allow written with NotResource grants every bucket except the listed ones.
ep_not_resource_elements := {"NotResource", "NotResources", "not_resources"}

ep_allows_by_exclusion(i, ep, name) {
    s := ep_allows(i, ep, name)[_]
    ep_not_resource_elements[k]
    object.get(s.stmt, k, null) != null
}

# A resolved data source can drop not_resources, so an Allow with no resource
# counts as NotResource.
ep_allows_by_exclusion(i, ep, name) {
    s := ep_allows(i, ep, name)[_]
    count(ep_resources(s)) == 0
}

# Policy documents holding statements the source does not show.
ep_unshown_documents(i, ep, name) := {n |
    src := endpoint_policies(i, ep, name)[_]
    n := policy_data_source_name(src.policy)
    tf_document_unshown(ep_documents(src)[_].block)
}

# --- Logic ---
# Fail 1: S3 endpoint with no policy defaults to full access.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    not has_any_policy(i, ep, name)

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
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    res := tf_unauthorized_resources(i, ep, name)[_]

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' Allow statements must name only authorized buckets and their objects: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' allows access to '%s', which does not name an authorized bucket in this Terraform source", [name, res]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 3: an Allow statement uses NotResource.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    ep_allows_by_exclusion(i, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' Allow statements must name authorized buckets in Resource: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' has an Allow written with NotResource, or with no Resource, which grants every bucket it does not list", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 4: the policy takes statements the source does not show.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    n := ep_unshown_documents(i, ep, name)[_]

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' policy must show every statement in the Terraform source, so that its Allow statements can be shown to name only authorized buckets: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy takes statements that data.aws_iam_policy_document.%s builds in a dynamic statement block or takes from other policy documents, which the Terraform source does not show and which may grant other buckets", [name, n]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 5: a policy whose statements the scan cannot read.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    src := endpoint_policies(i, ep, name)[_]
    not tf_policy_readable(src.doc, src.policy)
    count(tf_resolved_composed_from(src.doc, src.policy)) == 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' policy must show its statements, so that its Allow statements can be shown to name only authorized buckets: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy has content the scan cannot read, which may grant other buckets: %s", [name, tf_policy_unreadable_reason(src.policy)]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 6: a resolved policy matching composed documents, whose source and
# override statements the scan drops. Fail 5 does not report it again.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    src := endpoint_policies(i, ep, name)[_]
    names := tf_resolved_composed_from(src.doc, src.policy)
    count(names) > 0
    sources := concat(" or ", [sprintf("data.aws_iam_policy_document.%s", [n]) | n := sort(names)[_]])

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' policy must show every statement in the Terraform source, so that its Allow statements can be shown to name only authorized buckets: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy matches %s, which takes statements from other policy documents that the scan drops before the rule runs and that may grant other buckets", [name, sources]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# The <name> in data.aws_iam_policy_document.<name>.json, with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
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
