package wiz

import data.generic.terraform as terraLib

# --- Policy helpers ---
# Policies reach the matcher in three shapes: a JSON string with real IAM keys
# (jsonencode or heredoc), a JSON string with resolved data-source keys
# (Actions/Resources/Principals, condition values as arrays), or an unresolved
# reference to an aws_iam_policy_document data block (walked directly,
# lowercase names). The policy sits inline on the endpoint or on an associated
# aws_vpc_endpoint_policy.
is_s3_service(sn) { endswith(sn, ".s3") }

endpoint_policies(document, ep, name) := inline | assoc {
    inline := {ep.policy | is_string(ep.policy)}
    assoc := {p.policy |
        p := document.resource.aws_vpc_endpoint_policy[pn]
        terraLib.associatedResources(p, ep, pn, name, "vpc_endpoint_id", "id")
        is_string(p.policy)
    }
}

ep_json_statements(policy) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    doc := json.unmarshal(policy)
}

# Every statement of the endpoint's policies, tagged with the shape it came in.
ep_statements(document, ep, name) := json_stmts | hcl_stmts {
    policies := endpoint_policies(document, ep, name)
    json_stmts := {{"shape": "json", "stmt": stmt} | stmt := ep_json_statements(policies[_])[_]}
    hcl_stmts := {{"shape": "hcl", "stmt": stmt} |
        ds := document.data.aws_iam_policy_document[policy_data_source_name(policies[_])]
        stmt := terraLib.getArray(ds.statement)[_]
    }
}

ep_list(v) := v { is_array(v) } else := [v]

# effect is optional in the data source and defaults to Allow.
ep_effect(s) := lower(s.stmt.Effect) { s.shape == "json" }
ep_effect(s) := lower(object.get(s.stmt, "effect", "Allow")) { s.shape == "hcl" }

ep_actions(s) := array.concat(ep_list(object.get(s.stmt, "Action", [])), ep_list(object.get(s.stmt, "Actions", []))) { s.shape == "json" }
ep_actions(s) := ep_list(object.get(s.stmt, "actions", [])) { s.shape == "hcl" }

ep_resources(s) := array.concat(ep_list(object.get(s.stmt, "Resource", [])), ep_list(object.get(s.stmt, "Resources", []))) { s.shape == "json" }
ep_resources(s) := ep_list(object.get(s.stmt, "resources", [])) { s.shape == "hcl" }

ep_conditions(s) := [{"operator": lower(op), "key": lower(key), "values": ep_list(v)} | v := s.stmt.Condition[op][key]] { s.shape == "json" }
ep_conditions(s) := [{"operator": lower(c.test), "key": lower(c.variable), "values": ep_list(c.values)} | c := ep_list(object.get(s.stmt, "condition", []))[_]] { s.shape == "hcl" }

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

# A statement written with a Not element leaves something out, so it never
# counts as a covering deny.
ep_negated_elements := {
    "NotPrincipal", "NotAction", "NotResource",
    "NotPrincipals", "NotActions", "NotResources",
    "not_principals", "not_actions", "not_resources",
}

ep_negated(s) {
    ep_negated_elements[k]
    object.get(s.stmt, k, null) != null
}

# The deny must cover s3:PutObjectAcl, by name or by a pattern that matches it.
# An upload that sets an ACL needs s3:PutObjectAcl as well, so the deny also
# stops uploads with a public canned ACL.
ep_covers_put_object_acl(s) {
    tocm_iam_pattern_matches(lower(ep_actions(s)[_]), "s3:putobjectacl")
}

# --- Resource scope ---
# The endpoint reaches every bucket, so the deny must cover every object, in
# any of these partitions.
ep_partitions := {"aws", "aws-cn", "aws-us-gov"}

ep_resource_covers_objects(r) {
    tocm_s3_pattern_covers_all_objects(r, ep_partitions[_])
}

# Values that cannot be resolved statically are given the benefit of the
# doubt; a reference to one bucket is never all buckets.
ep_resource_covers_objects(r) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

ep_resource_covers_objects(r) {
    regex.match(`^(var|local|module|data)\.`, r)
}

# The canned ACL test must be the only condition; any extra key narrows the deny.
ep_sole_condition(s) := c {
    cs := ep_conditions(s)
    count(cs) == 1
    c := cs[0]
}

ep_public_acls := {"public-read", "public-read-write"}

ep_acl_operators := {"stringequals", "stringequalsifexists"}

# A Deny of s3:PutObjectAcl for all principals on every object, with the
# canned ACL test as its one condition.
ep_acl_deny(s) := c {
    ep_effect(s) == "deny"
    not ep_negated(s)
    ep_everyone(s)
    ep_covers_put_object_acl(s)
    ep_resource_covers_objects(ep_resources(s)[_])
    c := ep_sole_condition(s)
    ep_acl_operators[c.operator]
    c.key == "s3:x-amz-acl"
}

# Qualifying denies may split the two public canned ACLs between them.
ep_blocked_acls(document, ep, name) := {v |
    c := ep_acl_deny(ep_statements(document, ep, name)[_])
    v := c.values[_]
}

blocks_public_acl(document, ep, name) {
    count(ep_public_acls - ep_blocked_acls(document, ep, name)) == 0
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not blocks_public_acl(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must deny s3:PutObjectAcl for all principals on all objects when s3:x-amz-acl is public-read or public-read-write, with no other condition", [name]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy does not block both public canned ACLs at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# The data block a policy names: data.aws_iam_policy_document.<name>.json,
# written with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
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
