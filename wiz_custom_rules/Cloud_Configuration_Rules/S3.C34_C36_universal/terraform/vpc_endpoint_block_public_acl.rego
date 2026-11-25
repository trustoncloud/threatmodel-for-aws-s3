package wiz

import data.generic.terraform as terraLib

# --- Policy helpers ---
# A policy is IAM JSON, resolved data-source JSON (Actions, Resources) or a
# reference to an aws_iam_policy_document, on the endpoint or its policy.
is_s3_service(sn) { endswith(sn, ".s3") }

# The endpoint's own policy and each linked aws_vpc_endpoint_policy. Only one
# applies after apply, so each must satisfy the control on its own.
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

# One statement set per data block a policy names, or one from its JSON.
ep_views(src) := [ep_view(ds, src.policy) | ds := tf_documents_or_none(src.doc, src.policy)[_]]

ep_view(ds, policy) := json_stmts | hcl_stmts {
    json_stmts := {{"shape": "json", "stmt": stmt} | stmt := ep_json_statements(policy)[_]}
    hcl_stmts := {{"shape": "hcl", "stmt": stmt} | stmt := tf_deny_statements(ds)[_]}
}

ep_list(v) := v { is_array(v) } else := [v]

# effect defaults to Allow; the JSON Effect is case sensitive.
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

# Operator names are case sensitive; key names are not.
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

# A statement with a Not element leaves something out and never counts.
ep_negated_elements := {
    "NotPrincipal", "NotAction", "NotResource",
    "NotPrincipals", "NotActions", "NotResources",
    "not_principals", "not_actions", "not_resources",
}

ep_negated(s) {
    ep_negated_elements[k]
    object.get(s.stmt, k, null) != null
}

# s3:PutObjectVersionAcl applies when a request names a version. An upload
# with an ACL also needs s3:PutObjectAcl, so this deny covers uploads too.
ep_acl_actions := {"s3:PutObjectAcl", "s3:PutObjectVersionAcl"}

ep_covers_action(s, action) {
    tocm_iam_pattern_matches(lower(ep_actions(s)[_]), lower(action))
}

# --- Resource scope ---
# The endpoint reaches every bucket, so the deny must cover every object.
ep_partitions := {"aws", "aws-cn", "aws-us-gov"}

ep_resource_covers_objects(r) {
    tocm_s3_pattern_covers_all_objects(r, ep_partitions[_])
}

# An unresolved value counts as every object, unless it references a bucket.
ep_resource_covers_objects(r) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

ep_resource_covers_objects(r) {
    regex.match(`^(var|local|module|data)\.`, r)
}

ep_full_scope_deny(s) {
    tf_ep_deny(s)
    not ep_negated(s)
    ep_everyone(s)
    ep_resource_covers_objects(ep_resources(s)[_])
}

# A header test must be the only condition; two keys deny only with both.
ep_sole_condition(s) := c {
    cs := ep_conditions(s)
    count(cs) == 1
    c := cs[0]
}

# Canned ACLs that let anyone, or any AWS account, read the object.
ep_public_canned_acls := {"public-read", "public-read-write", "authenticated-read"}

ep_canned_acl_operators := {"StringEquals", "StringEqualsIfExists"}

# A canned ACL is one token, so a pattern covers each ACL it matches.
ep_canned_acl_pattern_operators := {"StringLike", "StringLikeIfExists"}

# Grant headers, and the groups whose grant makes an object public.
ep_grant_headers := {
    "s3:x-amz-grant-read",
    "s3:x-amz-grant-read-acp",
    "s3:x-amz-grant-write-acp",
    "s3:x-amz-grant-full-control",
}

ep_public_groups := {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}

ep_grant_operators := {"StringLike", "StringLikeIfExists"}

# A grant header lists comma-separated grantees, so only a pattern with "*" at
# both ends covers the group URI wherever it sits.
ep_pattern_covers_group(p, uri) {
    is_string(p)
    startswith(p, "*")
    endswith(p, "*")
    tocm_iam_pattern_matches(p, uri)
}

# Every pairing of action and header value the policy must deny.
ep_required[r] {
    action := ep_acl_actions[_]
    acl := ep_public_canned_acls[_]
    r := {"action": action, "key": "s3:x-amz-acl", "value": acl}
}

ep_required[r] {
    action := ep_acl_actions[_]
    header := ep_grant_headers[_]
    ep_public_groups[uri]
    r := {"action": action, "key": header, "value": uri}
}

ep_condition_covers(c, value) {
    c.key == "s3:x-amz-acl"
    ep_canned_acl_operators[c.operator]
    c.values[_] == value
}

ep_condition_covers(c, value) {
    c.key == "s3:x-amz-acl"
    ep_canned_acl_pattern_operators[c.operator]
    tocm_iam_pattern_matches(c.values[_], value)
}

ep_condition_covers(c, uri) {
    ep_grant_headers[c.key]
    ep_grant_operators[c.operator]
    ep_pattern_covers_group(c.values[_], uri)
}

# Null "false" denies every request that carries the header, whatever it names.
ep_condition_covers(c, _) {
    ep_grant_headers[c.key]
    c.operator == "Null"
    ep_is_false(c.values[_])
}

ep_is_false(v) { v == false }

ep_is_false(v) {
    is_string(v)
    lower(v) == "false"
}

# Qualifying denies may split the actions, headers and values between them.
ep_view_covered(v) := {r |
    s := v[_]
    ep_full_scope_deny(s)
    c := ep_sole_condition(s)
    r := ep_required[_]
    r.key == c.key
    ep_covers_action(s, r.action)
    ep_condition_covers(c, r.value)
} | ep_view_covered_unconditional(v)

# A deny with no condition blocks every ACL write of the actions it covers.
ep_view_covered_unconditional(v) := {r |
    s := v[_]
    ep_full_scope_deny(s)
    count(ep_conditions(s)) == 0
    r := ep_required[_]
    ep_covers_action(s, r.action)
}

# A data block defined in several files covers only what each copy covers.
ep_source_covered(src) := {r |
    views := ep_views(src)
    r := ep_required[_]
    count([v | v := views[_]; not ep_view_covered(v)[r]]) == 0
}

# Every policy source of the endpoint must cover each pairing on its own.
ep_covered(i, ep, name) := {r |
    sources := endpoint_policies(i, ep, name)
    count(sources) > 0
    r := ep_required[_]
    count({src | src := sources[_]; not ep_source_covered(src)[r]}) == 0
}

ep_missing_text(missing) := concat(", ", sort([ep_describe(r) | r := missing[_]]))

ep_actual_value(i, ep, name, missing) := sprintf("S3 VPC endpoint '%s' sets more than one endpoint policy (its policy argument or aws_vpc_endpoint_policy resources) and only one applies after apply, so each must deny every pairing on its own, and at least one does not deny: %s", [name, ep_missing_text(missing)]) {
    count(endpoint_policies(i, ep, name)) > 1
} else := sprintf("S3 VPC endpoint '%s' policy does not deny: %s", [name, ep_missing_text(missing)])

ep_describe(r) := sprintf("%s with %s %s", [r.action, r.key, r.value]) {
    r.key == "s3:x-amz-acl"
} else := sprintf("%s with %s naming %s", [r.action, r.key, ep_public_groups[r.value]])

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    not tf_not_created(ep)
    is_s3_service(ep.service_name)
    missing := ep_required - ep_covered(i, ep, name)
    count(missing) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must deny s3:PutObjectAcl and s3:PutObjectVersionAcl for all principals on all objects when s3:x-amz-acl is public-read, public-read-write or authenticated-read (StringEquals, or a matching StringLike pattern), and when any of the four grant headers names the AllUsers or AuthenticatedUsers group (StringLike \"*<group URI>*\", or Null false), each header in its own statement; a Deny with no condition covers everything. Only request headers are checked, not an ACL in the request body", [name]),
        "keyActualValue": ep_actual_value(i, ep, name, missing),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# The <name> in data.aws_iam_policy_document.<name>.json, with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}

# The data blocks a policy names, else [{}] so its JSON is read alone.
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
