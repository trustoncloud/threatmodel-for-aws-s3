package wiz

import data.generic.terraform as terraLib

# Cloud matcher is N/A: SCPs are not an ingested Wiz native type. This
# Terraform matcher enforces the control at build time.
#
# Scope: only Service Control Policies. In an org with multiple SCPs, each is
# checked independently; keep the S3 secure-transport enforcement in the
# SCP(s) covered by this scan (or suppress on SCPs that serve another purpose).

# --- Policy helpers ---
is_scp(res) { res.type == "SERVICE_CONTROL_POLICY" }
is_scp(res) { not res.type }

partitions := {"aws", "aws-cn", "aws-us-gov"}

all_s3_action(a) { lower(a) == "s3:*" }
all_s3_action(a) { a == "*" }

# Every S3 resource. A request through an access point names the access point
# ARN, so a Deny on buckets and objects alone ("arn:aws:s3:::*") leaves it out.
all_s3_resource(r) { r == "*" }
all_s3_resource(r) { tocm_iam_pattern_covers_prefix(r, sprintf("arn:%s:s3:", [partitions[_]])) }

# A condition value may be one value or a list, and a number or a string.
scp_list(v) := v { is_array(v) } else := [v]

value_false(v) { v == "false" }
value_false(v) { v == false }

# One condition as {operator, key, values}. Only the plain operator and its
# IfExists form count.
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

# The transport test must be the only condition; any extra key narrows the Deny.
json_condition(stmt) := {"operator": operator, "key": lower(key), "values": scp_list(v)} {
    count(stmt.Condition) == 1
    v := stmt.Condition[operator][key]
    count(stmt.Condition[operator]) == 1
}

json_enforces(res, kind) {
    stmt := json_statements(res)[_]
    stmt.Effect == "Deny"
    not json_has_not_element(stmt)
    all_s3_action(stmt_actions(stmt)[_])
    all_s3_resource(stmt_resources(stmt)[_])
    condition_enforces(json_condition(stmt), kind)
}

# --- Data source content ---
# content = data.aws_iam_policy_document.<name>.json, read from the data block
# of that exact name in the same file.
content_data_source(res) := m[1] {
    is_string(res.content)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json\s*\}?\s*$`, res.content, 1)[0]
}

hcl_has_not_element(stmt) {
    k := {"not_actions", "not_resources"}[_]
    object.get(stmt, k, null) != null
}

hcl_enforces(document, res, kind) {
    ds := document.data.aws_iam_policy_document[content_data_source(res)]
    stmt := terraLib.getArray(ds.statement)[_]
    lower(stmt.effect) == "deny"
    not hcl_has_not_element(stmt)
    all_s3_action(terraLib.getArray(stmt.actions)[_])
    all_s3_resource(terraLib.getArray(stmt.resources)[_])
    conds := terraLib.getArray(stmt.condition)
    count(conds) == 1
    c := conds[0]
    condition_enforces({"operator": c.test, "key": lower(c.variable), "values": scp_list(c.values)}, kind)
}

enforces(document, res, kind) { json_enforces(res, kind) }
enforces(document, res, kind) { hcl_enforces(document, res, kind) }

content_readable(document, res) { json_doc(res) }
content_readable(document, res) { document.data.aws_iam_policy_document[content_data_source(res)] }

# --- Logic ---
# Both protections are required; each missing protection is its own finding.
protections := {
    "transport": {
        "when": "when aws:SecureTransport is false",
        "missing": "has no Deny of unencrypted requests at that scope",
    },
    "tls": {
        "when": "when s3:TlsVersion is below 1.2",
        "missing": "has no Deny of TLS versions below 1.2 at that scope",
    },
}

WizPolicy[result] {
    document := input.document[i]
    res := document.resource.aws_organizations_policy[name]
    is_scp(res)
    content_readable(document, res)
    protection := protections[kind]
    not enforces(document, res, kind)

    result := {
        "documentId": document.id,
        "resourceType": "aws_organizations_policy",
        "resourceName": terraLib.get_resource_name(res, name),
        "searchKey": sprintf("aws_organizations_policy[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("SCP '%s' must Deny all S3 actions on all S3 resources %s, with no other condition", [name, protection.when]),
        "keyActualValue": sprintf("SCP '%s' %s", [name, protection.missing]),
        "resourceTags": terraLib.get_resource_tags(res),
    }
}

# Content the source does not show is one finding for both protections.
WizPolicy[result] {
    document := input.document[i]
    res := document.resource.aws_organizations_policy[name]
    is_scp(res)
    not content_readable(document, res)

    result := {
        "documentId": document.id,
        "resourceType": "aws_organizations_policy",
        "resourceName": terraLib.get_resource_name(res, name),
        "searchKey": sprintf("aws_organizations_policy[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("SCP '%s' must Deny all S3 actions on all S3 resources when aws:SecureTransport is false and when s3:TlsVersion is below 1.2, each with no other condition", [name]),
        "keyActualValue": sprintf("SCP '%s' takes its content from a value the Terraform source does not show, so its Deny statements cannot be read", [name]),
        "resourceTags": terraLib.get_resource_tags(res),
    }
}

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
