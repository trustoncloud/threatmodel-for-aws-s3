package wiz

import data.generic.terraform as terraLib

# --- Policy helpers ---
# A policy is IAM JSON, resolved data source JSON (Actions, Resources), or a
# reference to an aws_iam_policy_document read as HCL.
is_s3_service(sn) { endswith(sn, ".s3") }

# The policy argument and each linked aws_vpc_endpoint_policy overwrite each
# other, so each must satisfy the control on its own.
endpoint_policies(i, ep, name) := inline | assoc {
    inline := {src | is_string(ep.policy); src := {"id": "policy argument", "doc": i, "policy": ep.policy}}
    assoc := {{"id": sprintf("aws_vpc_endpoint_policy.%s", [pn]), "doc": j, "policy": p.policy} |
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

# One statement set per data block the source names (each must hold the
# Deny), or one set read from its JSON.
ep_views(src) := [ep_view(ds, src.policy) | ds := tf_documents_or_none(src.doc, src.policy)[_]]

ep_view(ds, policy) := json_stmts | hcl_stmts {
    json_stmts := {{"shape": "json", "stmt": stmt} | stmt := ep_json_statements(policy)[_]}
    hcl_stmts := {{"shape": "hcl", "stmt": stmt} | stmt := tf_deny_statements(ds)[_]}
}

ep_list(v) := v { is_array(v) } else := [v]

# HCL effect defaults to Allow; the JSON Effect is case sensitive.
tf_ep_deny(s) {
    s.shape == "json"
    s.stmt.Effect == "Deny"
}

tf_ep_deny(s) {
    s.shape == "hcl"
    lower(object.get(s.stmt, "effect", "Allow")) == "deny"
}

ep_actions(s) := array.concat(ep_list(object.get(s.stmt, "Action", [])), ep_list(object.get(s.stmt, "Actions", []))) { s.shape == "json" }
ep_actions(s) := ep_list(object.get(s.stmt, "actions", [])) { s.shape == "hcl" }

ep_resources(s) := array.concat(ep_list(object.get(s.stmt, "Resource", [])), ep_list(object.get(s.stmt, "Resources", []))) { s.shape == "json" }
ep_resources(s) := ep_list(object.get(s.stmt, "resources", [])) { s.shape == "hcl" }

# Operators match by exact name; condition key names are not case sensitive.
ep_conditions(s) := [{"operator": op, "key": lower(key), "values": ep_list(v)} | v := s.stmt.Condition[op][key]] { s.shape == "json" }
ep_conditions(s) := [{"operator": c.test, "key": lower(c.variable), "values": ep_list(c.values)} | c := ep_list(object.get(s.stmt, "condition", []))[_]] { s.shape == "hcl" }

ep_wildcard(v) { ep_list(v)[_] == "*" }

ep_everyone(s) { s.shape == "json"; ep_wildcard(s.stmt.Principal) }
ep_everyone(s) { s.shape == "json"; ep_wildcard(s.stmt.Principal.AWS) }
ep_everyone(s) { s.shape == "json"; ep_wildcard(s.stmt.Principals["*"]) }
ep_everyone(s) { s.shape == "json"; ep_wildcard(s.stmt.Principals.AWS) }

ep_everyone(s) {
    s.shape == "hcl"
    p := ep_list(s.stmt.principals)[_]
    {"*", "AWS"}[p.type]
    ep_wildcard(p.identifiers)
}

# A statement with a Not element never counts.
ep_negated_elements := {
    "NotPrincipal", "NotAction", "NotResource",
    "NotPrincipals", "NotActions", "NotResources",
    "not_principals", "not_actions", "not_resources",
}

ep_negated(s) {
    ep_negated_elements[k]
    object.get(s.stmt, k, null) != null
}

ep_all_s3_actions := {"*", "s3:*"}

ep_all_actions(s) { ep_all_s3_actions[lower(ep_actions(s)[_])] }

# --- Resource scope ---
# The Deny must cover every bucket and object, in any of these partitions.
ep_partitions := {"aws", "aws-cn", "aws-us-gov"}

ep_resource_covers_all(r) {
    tocm_s3_pattern_covers_all(r, ep_partitions[_])
}

# An unresolved value gets the benefit of the doubt, unless it names a bucket.
ep_resource_covers_all(r) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

ep_resource_covers_all(r) {
    regex.match(`^(var|local|module|data)\.`, r)
}

ep_full_scope_deny(s) {
    tf_ep_deny(s)
    not ep_negated(s)
    ep_everyone(s)
    ep_all_actions(s)
    ep_resource_covers_all(ep_resources(s)[_])
}

ep_false(v) { v == "false" }
ep_false(v) { v == false }

ep_test(c, "transport") {
    {"Bool", "BoolIfExists"}[c.operator]
    c.key == "aws:securetransport"
    ep_false(c.values[_])
}

ep_test(c, "tls") {
    {"NumericLessThan", "NumericLessThanIfExists"}[c.operator]
    c.key == "s3:tlsversion"
    to_number(c.values[_]) >= 1.2
}

# A Deny may exempt AWS services with aws:PrincipalIsAWSService false. Only
# BoolIfExists keeps the Deny on anonymous requests, which omit that key.
ep_service_exemption(c) {
    c.operator == "BoolIfExists"
    c.key == "aws:principalisawsservice"
    count(c.values) > 0
    count([v | v := c.values[_]; not ep_false(v)]) == 0
}

# The transport test stands alone or beside the service exemption; any other
# key narrows the deny.
ep_qualifies(s, kind) {
    cs := ep_conditions(s)
    count(cs) == 1
    ep_test(cs[0], kind)
}

ep_qualifies(s, kind) {
    cs := ep_conditions(s)
    count(cs) == 2
    some i
    ep_test(cs[i], kind)
    ep_service_exemption(cs[1 - i])
}

ep_view_enforces(v, kind) {
    s := v[_]
    ep_full_scope_deny(s)
    ep_qualifies(s, kind)
}

ep_source_enforces(src, kind) {
    views := ep_views(src)
    count([v | v := views[_]; not ep_view_enforces(v, kind)]) == 0
}

# Every policy source of the endpoint must hold each Deny on its own.
ep_enforces(i, ep, name, kind) {
    sources := endpoint_policies(i, ep, name)
    count(sources) > 0
    count({src | src := sources[_]; not ep_source_enforces(src, kind)}) == 0
}

ep_actual_value(i, ep, name, missing) := sprintf("S3 VPC endpoint '%s' sets more than one endpoint policy (its policy argument or aws_vpc_endpoint_policy resources) and only one applies after apply, so each must hold %s at that scope, and at least one does not", [name, concat(" and ", missing)]) {
    count(endpoint_policies(i, ep, name)) > 1
} else := sprintf("S3 VPC endpoint '%s' policy lacks %s at that scope", [name, concat(" and ", missing)])

ep_missing(i, ep, name) := [label |
    kinds := [["transport", "a Deny of unencrypted requests (aws:SecureTransport false)"], ["tls", "a Deny of TLS versions below 1.2 (s3:TlsVersion)"]]
    k := kinds[_]
    not ep_enforces(i, ep, name, k[0])
    label := k[1]
]

# --- Logic ---
# Both Denies are required: a plain HTTP request carries no TLS version. An
# endpoint with no policy has full access and fails.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    missing := ep_missing(i, ep, name)
    count(missing) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must have a Deny for all principals and all S3 actions on all buckets and objects when aws:SecureTransport is false, and another when s3:TlsVersion is below 1.2, each with no other condition than an optional aws:PrincipalIsAWSService false under BoolIfExists", [name]),
        "keyActualValue": ep_actual_value(i, ep, name, missing),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# policy = data.aws_iam_policy_document.<name>.json, with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}

# A policy naming no data block in the scan is read from its JSON alone ([{}]).
tf_documents_or_none(i, v) := docs {
    docs := [c.block | c := tf_lookup(i, "data", "aws_iam_policy_document", policy_data_source_name(v))[_]]
    count(docs) > 0
} else := [{}]

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
# --- toc-match begin: iampattern v1 ---
# An IAM policy pattern as a regular expression: "*" is any run of characters
# ("/", ":" and a line break included), "?" is any one character, and every
# other character stands for itself.
tocm_iam_pattern_regex(p) := concat("", ["(?s)^", body, "$"]) {
    is_string(p)
    body := strings.replace_n({
        "\\": "\\\\", ".": "\\.", "+": "\\+", "(": "\\(", ")": "\\)", "|": "\\|",
        "[": "\\[", "]": "\\]", "{": "\\{", "}": "\\}", "^": "\\^", "$": "\\$",
        "*": ".*", "?": "."
    }, p)
}

# The pattern matches this one value.
tocm_iam_pattern_matches(p, value) {
    is_string(value)
    regex.match(tocm_iam_pattern_regex(p), value)
}

# The pattern matches every value that starts with base. It must end in "*",
# and what stands before that "*" must match base or the start of base. So
# "arn:aws:s3:::logs/*" and "arn:aws:s3:::lo*" cover everything under
# "arn:aws:s3:::logs/", and "arn:aws:s3:::logs/a*" does not.
tocm_iam_pattern_covers_prefix(p, base) {
    is_string(p)
    is_string(base)
    endswith(p, "*")
    head := tocm_iam_pattern_regex(substring(p, 0, count(p) - 1))
    n := numbers.range(0, count(base))[_]
    regex.match(head, substring(base, 0, n))
}

# The pattern matches every value made of base and at least one more
# character. Use it where that part is never empty, such as an object key
# after "<bucket ARN>/": "arn:aws:s3:::logs/?*" then covers every object of
# the bucket. What stands before the final "*" must match base or the start of
# base, or match base and any one character; a match for two different
# characters can only come from a wildcard.
tocm_iam_pattern_covers_nonempty(p, base) {
    tocm_iam_pattern_covers_prefix(p, base)
}

tocm_iam_pattern_covers_nonempty(p, base) {
    is_string(p)
    is_string(base)
    endswith(p, "*")
    head := tocm_iam_pattern_regex(substring(p, 0, count(p) - 1))
    regex.match(head, concat("", [base, "a"]))
    regex.match(head, concat("", [base, "b"]))
}

# Every object of one bucket, given the bucket ARN. An object key is never
# empty.
tocm_s3_pattern_covers_objects(p, bucket_arn) {
    tocm_iam_pattern_covers_nonempty(p, concat("", [bucket_arn, "/"]))
}

# Every bucket of a partition, and every object in them. A bucket name is
# never empty.
tocm_s3_pattern_covers_all(p, partition) {
    tocm_iam_pattern_covers_nonempty(p, concat("", ["arn:", partition, ":s3:::"]))
}

# Every object of every bucket of a partition; "arn:<partition>:s3:::*/*" is
# the usual way to write it, and "?*" may stand for either "*".
tocm_s3_pattern_covers_all_objects(p, partition) {
    tocm_s3_pattern_covers_all(p, partition)
}

tocm_s3_pattern_covers_all_objects(p, partition) {
    names := {"*", "?*"}
    p == concat("", ["arn:", partition, ":s3:::", names[_], "/", names[_]])
}
# --- toc-match end: iampattern v1 ---
