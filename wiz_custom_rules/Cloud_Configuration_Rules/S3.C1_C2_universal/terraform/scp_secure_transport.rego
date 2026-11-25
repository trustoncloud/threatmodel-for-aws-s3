package wiz

import data.generic.terraform as terraLib

# Scope: the SCPs attached to each organization root, judged together across
# the scan. SCPs attached to an OU or an account are not judged.

# --- Policy helpers ---
# A policy of another literal type (a tag or backup policy) is out of scope;
# a type the source does not show may be an SCP.
other_policy_type(res) {
    is_string(res.type)
    regex.match(`^[A-Z0-9_]+$`, res.type)
    res.type != "SERVICE_CONTROL_POLICY"
}

is_scp(res) { not other_policy_type(res) }

partitions := {"aws", "aws-cn", "aws-us-gov"}

all_s3_action(a) { lower(a) == "s3:*" }
all_s3_action(a) { a == "*" }

# Every S3 resource; "arn:aws:s3:::*" alone misses access point requests.
all_s3_resource(r) { r == "*" }
all_s3_resource(r) { tocm_iam_pattern_covers_prefix(r, sprintf("arn:%s:s3:", [partitions[_]])) }

# A condition value may be one value or a list, and a number or a string.
scp_list(v) := v { is_array(v) } else := [v]

value_false(v) { v == "false" }
value_false(v) { v == false }

# One condition test as {operator, key, values}. Operators match by exact
# name; condition key names are not case sensitive.
condition_enforces(c, "transport") {
    {"Bool", "BoolIfExists"}[c.operator]
    c.key == "aws:securetransport"
    value_false(c.values[_])
}

condition_enforces(c, "tls") {
    {"NumericLessThan", "NumericLessThanIfExists"}[c.operator]
    c.key == "s3:tlsversion"
    to_number(c.values[_]) >= 1.2
}

# A Deny may exempt AWS services with aws:PrincipalIsAWSService false. SCP
# principals always carry that key, so Bool and BoolIfExists act the same.
service_exemption(c) {
    {"Bool", "BoolIfExists"}[c.operator]
    c.key == "aws:principalisawsservice"
    count(c.values) > 0
    count([v | v := c.values[_]; not value_false(v)]) == 0
}

# The transport test stands alone or beside the service exemption; any other
# key narrows the Deny.
conditions_enforce(cs, kind) {
    count(cs) == 1
    condition_enforces(cs[0], kind)
}

conditions_enforce(cs, kind) {
    count(cs) == 2
    some i
    condition_enforces(cs[i], kind)
    service_exemption(cs[1 - i])
}

# --- JSON content ---
# Heredoc and jsonencode content is IAM JSON. A resolved policy document data
# source arrives as JSON too, with Statements, Actions and Resources.
json_doc(res) := doc {
    is_string(res.content)
    doc := json.unmarshal(res.content)
    is_object(doc)
}

json_statements(res) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    doc := json_doc(res)
}

stmt_actions(stmt) := terraLib.getArray(stmt.Action)
stmt_actions(stmt) := terraLib.getArray(stmt.Actions)

stmt_resources(stmt) := terraLib.getArray(stmt.Resource)
stmt_resources(stmt) := terraLib.getArray(stmt.Resources)

# NotAction and NotResource leave something out, so such a Deny never counts.
json_has_not_element(stmt) {
    k := {"NotAction", "NotActions", "NotResource", "NotResources"}[_]
    object.get(stmt, k, null) != null
}

json_conditions(stmt) := [{"operator": op, "key": lower(key), "values": scp_list(v)} | v := stmt.Condition[op][key]]

json_enforces(res, kind) {
    stmt := json_statements(res)[_]
    stmt.Effect == "Deny"
    not json_has_not_element(stmt)
    all_s3_action(stmt_actions(stmt)[_])
    all_s3_resource(stmt_resources(stmt)[_])
    conditions_enforce(json_conditions(stmt), kind)
}

# --- Data source content ---
# content = data.aws_iam_policy_document.<name>.json or .minified_json.
content_data_source(res) := m[1] {
    is_string(res.content)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, res.content, 1)[0]
}

content_documents(j, res) := [c.block | c := tf_lookup(j, "data", "aws_iam_policy_document", content_data_source(res))[_]]

hcl_has_not_element(stmt) {
    k := {"not_actions", "not_resources"}[_]
    object.get(stmt, k, null) != null
}

hcl_conditions(stmt) := [{"operator": c.test, "key": lower(c.variable), "values": scp_list(c.values)} | c := terraLib.getArray(stmt.condition)[_]]

document_enforces(ds, kind) {
    stmt := tf_deny_statements(ds)[_]
    lower(stmt.effect) == "deny"
    not hcl_has_not_element(stmt)
    all_s3_action(terraLib.getArray(stmt.actions)[_])
    all_s3_resource(terraLib.getArray(stmt.resources)[_])
    conditions_enforce(hcl_conditions(stmt), kind)
}

# A data block found in more than one file must hold the Deny in each.
hcl_enforces(j, res, kind) {
    docs := content_documents(j, res)
    count(docs) > 0
    count([ds | ds := docs[_]; not document_enforces(ds, kind)]) == 0
}

enforces(j, res, kind) { json_enforces(res, kind) }
enforces(j, res, kind) { hcl_enforces(j, res, kind) }

content_readable(j, res) { json_doc(res) }
content_readable(j, res) { count(content_documents(j, res)) > 0 }

# --- Attachments ---
attachments := {a |
    some i, name
    att := input.document[i].resource.aws_organizations_policy_attachment[name]
    not tf_not_created(att)
    a := {"doc": i, "name": name, "att": att}
}

# policy_id = aws_organizations_policy.<name>.id, with or without "${}".
policy_ref(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*aws_organizations_policy\.([A-Za-z0-9_-]+)\.id\s*\}?\s*$`, v, 1)[0]
}

# Named policies as [file index, name]: own file first, else the whole scan.
named_policies(a) := own {
    n := policy_ref(a.att.policy_id)
    own := {[a.doc, n] | input.document[a.doc].resource.aws_organizations_policy[n]}
    count(own) > 0
} else := {[j, n] |
    n := policy_ref(a.att.policy_id)
    input.document[j].resource.aws_organizations_policy[n]
}

policy_res(p) := input.document[p[0]].resource.aws_organizations_policy[p[1]]

named_scps(a) := {p | p := named_policies(a)[_]; is_scp(policy_res(p))}

# An attachment of a tag, backup or other non-SCP policy is out of scope.
attaches_other_type(a) {
    count(named_policies(a)) > 0
    count(named_scps(a)) == 0
}

# The default SCP Organizations attaches everywhere; it holds no Deny.
full_access_scp(a) { a.att.policy_id == "p-FullAWSAccess" }

# The source shows the statements of the SCP the attachment names.
policy_shown(a) { full_access_scp(a) }

policy_shown(a) {
    scps := named_scps(a)
    count(scps) > 0
    count([p | p := scps[_]; not content_readable(p[0], policy_res(p))]) == 0
}

# An SCP that is never created holds no Deny.
attachment_enforces(a, kind) {
    p := named_scps(a)[_]
    not tf_not_created(policy_res(p))
    enforces(p[0], policy_res(p), kind)
}

# --- Targets ---
# A root is a literal ID or roots[0].id of an organization. Each ID and each
# organization address counts as its own root.
root_id_pattern := `^r-[0-9a-z]{4,32}$`

org_root_ref_pattern := `^\s*(?:\$\{)?\s*((?:data\.)?aws_organizations_organization\.[A-Za-z0-9_-]+)\.roots(?:\[0\]|\.0)\.id\s*\}?\s*$`

# An OU or an account, by literal ID or by reference.
other_target_id_pattern := `^(?:ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|[0-9]{12})$`

other_target_ref_pattern := `^\s*(?:\$\{)?\s*(?:data\.)?aws_organizations_(?:organizational_unit|account)\.[A-Za-z0-9_-]+\.id\s*\}?\s*$`

target_id(a) := t {
    t := object.get(a.att, "target_id", "")
    is_string(t)
} else := ""

root_key(a) := target_id(a) {
    regex.match(root_id_pattern, target_id(a))
} else := m[1] {
    m := regex.find_all_string_submatch_n(org_root_ref_pattern, target_id(a), 1)[0]
}

targets_other(a) { regex.match(other_target_id_pattern, target_id(a)) }
targets_other(a) { regex.match(other_target_ref_pattern, target_id(a)) }

root_attachments := {a |
    a := attachments[_]
    not attaches_other_type(a)
    root_key(a)
}

unknown_target_attachments := {a |
    a := attachments[_]
    not attaches_other_type(a)
    not root_key(a)
    not targets_other(a)
}

org_resources := {o |
    some i, name
    org := input.document[i].resource.aws_organizations_organization[name]
    not tf_not_created(org)
    o := {"doc": i, "name": name, "key": sprintf("aws_organizations_organization.%s", [name])}
}

org_keys := {o.key | o := org_resources[_]}

roots := {root_key(a) | a := root_attachments[_]} | org_keys

# --- Logic ---
# Each root holds both Denies between the SCPs attached to it.
root_enforces(key, kind) {
    a := root_attachments[_]
    root_key(a) == key
    attachment_enforces(a, kind)
}

protections := {
    "transport": "a Deny of unencrypted requests (aws:SecureTransport false)",
    "tls": "a Deny of TLS versions below 1.2 (s3:TlsVersion)",
}

root_missing(key) := [label | k := ["transport", "tls"][_]; not root_enforces(key, k); label := protections[k]]

root_fails(key) { count(root_missing(key)) > 0 }

every_root_passes {
    count(roots) > 0
    count({k | k := roots[_]; root_fails(k)}) == 0
}

expected_root := "The SCPs attached to each organization root must, between them, Deny all S3 actions on all S3 resources when aws:SecureTransport is false and when s3:TlsVersion is below 1.2, each with no other condition than an optional aws:PrincipalIsAWSService false"

org_actual(o) := sprintf("No SCP in this scan is attached to the root of organization '%s', so that root holds no Deny of unencrypted S3 requests or of TLS versions below 1.2", [o.name]) {
    count({a | a := root_attachments[_]; root_key(a) == o.key}) == 0
} else := sprintf("The SCPs attached to the root of organization '%s' in this scan lack %s", [o.name, concat(" and ", root_missing(o.key))])

# A root the scan defines as an organization resource carries the finding there.
WizPolicy[result] {
    o := org_resources[_]
    root_fails(o.key)
    document := input.document[o.doc]
    org := document.resource.aws_organizations_organization[o.name]

    result := {
        "documentId": document.id,
        "resourceType": "aws_organizations_organization",
        "resourceName": terraLib.get_resource_name(org, o.name),
        "searchKey": sprintf("aws_organizations_organization[%s]", [o.name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": expected_root,
        "keyActualValue": org_actual(o),
        "resourceTags": terraLib.get_resource_tags(org),
    }
}

# For any other root, each attachment whose SCP is shown carries the finding.
WizPolicy[result] {
    a := root_attachments[_]
    key := root_key(a)
    not org_keys[key]
    root_fails(key)
    policy_shown(a)
    document := input.document[a.doc]

    result := {
        "documentId": document.id,
        "resourceType": "aws_organizations_policy_attachment",
        "resourceName": terraLib.get_resource_name(a.att, a.name),
        "searchKey": sprintf("aws_organizations_policy_attachment[%s]", [a.name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": expected_root,
        "keyActualValue": sprintf("Attachment '%s' targets the organization root %s, and the SCPs attached to that root in this scan lack %s", [a.name, key, concat(" and ", root_missing(key))]),
        "resourceTags": terraLib.get_resource_tags(a.att),
    }
}

# An attachment the source does not fully show is a finding, unless its root
# (or, for an unknown target, every root) already holds both Denies.
unshown_reason(a) := sprintf("Attachment '%s' attaches to the organization root %s a policy whose content the Terraform source does not show (policy_id %v)", [a.name, root_key(a), a.att.policy_id]) {
    root_attachments[a]
    not policy_shown(a)
    root_fails(root_key(a))
} else := sprintf("Attachment '%s' attaches a policy whose content the Terraform source does not show (policy_id %v) to a target it does not show (target_id %v), so it may be an organization root", [a.name, a.att.policy_id, target_id(a)]) {
    unknown_target_attachments[a]
    not every_root_passes
    not policy_shown(a)
} else := sprintf("Attachment '%s' attaches to a target the Terraform source does not show (target_id %v), so it may be an organization root", [a.name, target_id(a)]) {
    unknown_target_attachments[a]
    not every_root_passes
}

WizPolicy[result] {
    a := attachments[_]
    reason := unshown_reason(a)
    document := input.document[a.doc]

    result := {
        "documentId": document.id,
        "resourceType": "aws_organizations_policy_attachment",
        "resourceName": terraLib.get_resource_name(a.att, a.name),
        "searchKey": sprintf("aws_organizations_policy_attachment[%s]", [a.name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "The attachment must show its target and the content of the SCP it attaches, so that the SCPs on each organization root can be judged",
        "keyActualValue": reason,
        "resourceTags": terraLib.get_resource_tags(a.att),
    }
}

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
