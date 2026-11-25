package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_access_points := {
    "arn:aws:s3:us-east-1:123456789012:accesspoint/authorized-ap",
}

# --- Policy helpers ---
# A policy is a JSON string with IAM keys or resolved data-source keys
# (Actions, Resources), or a reference to an aws_iam_policy_document block.

# Condition operator names are case sensitive, so they match by exact name.
restriction_operators := {"StringNotEquals", "StringNotEqualsIfExists"}

stmt_actions(stmt) := terraLib.getArray(stmt.Action)
stmt_actions(stmt) := terraLib.getArray(stmt.Actions)

stmt_resources(stmt) := terraLib.getArray(stmt.Resource)
stmt_resources(stmt) := terraLib.getArray(stmt.Resources)

# IAM action names are not case sensitive, so they are compared in lower case.
tf_all_s3_actions := {"s3:*", "*"}

json_covers_all_s3(stmt) { tf_all_s3_actions[lower(stmt_actions(stmt)[_])] }

hcl_covers_all_s3(stmt) { tf_all_s3_actions[lower(terraLib.getArray(stmt.actions)[_])] }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

json_everyone(stmt) { stmt.Principal == "*" }
json_everyone(stmt) { wildcard(stmt.Principal.AWS) }
json_everyone(stmt) { wildcard(stmt.Principals["*"]) }
json_everyone(stmt) { wildcard(stmt.Principals.AWS) }

hcl_everyone(stmt) {
    p := terraLib.getArray(stmt.principals)[_]
    {"*", "AWS"}[p.type]
    wildcard(p.identifiers)
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

# A statement with NotResource, NotAction or NotPrincipal never counts.
not_keys := {
    "NotResource", "NotResources", "NotAction", "NotActions", "NotPrincipal", "NotPrincipals",
    "not_resources", "not_actions", "not_principals",
}

is_set_value(v) {
    v != null
    v != []
    v != {}
    v != ""
}

json_uses_not(stmt) { is_set_value(stmt[not_keys[_]]) }

hcl_uses_not(stmt) { is_set_value(stmt[not_keys[_]]) }

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

# Denies for everyone on all S3 actions conditioned only on the access point,
# read from the policy's JSON and from data block ds ({} when it names none).
ap_restrictions(ds, pol) := json_rs | hcl_rs {
    json_rs := {{"resources": stmt_resources(stmt), "aps": terraLib.getArray(val)} |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        not json_uses_not(stmt)
        json_covers_all_s3(stmt)
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        restriction_operators[operator]
        count(conditions) == 1
        val := conditions[key]
        lower(key) == "s3:dataaccesspointarn"
    }
    hcl_rs := {{"resources": terraLib.getArray(stmt.resources), "aps": terraLib.getArray(c.values)} |
        stmt := tf_deny_statements(ds)[_]
        lower(stmt.effect) == "deny"
        not hcl_uses_not(stmt)
        hcl_covers_all_s3(stmt)
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        c := conds[0]
        restriction_operators[c.test]
        lower(c.variable) == "s3:dataaccesspointarn"
    }
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

# The data blocks a source names, each read on its own.
source_documents(src) := tf_documents_or_none(src.doc, object.get(src.pol, "policy", null))

# An unauthorized access point in any data block a source names is reported.
bucket_restrictions(i, bucket, name) := {r |
    src := bucket_policies(i, bucket, name)[_]
    ds := source_documents(src)[_]
    r := ap_restrictions(ds, src.pol)[_]
}

# --- Resource scope ---
# The deny must reach every object; the bucket ARN is optional, since bucket
# settings calls cannot go through an access point.

partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

tf_covers_every_object(r, bucket, name) {
    r == "*"
}

# A reference to this bucket: judge what follows it, with "x" as the ARN.
tf_covers_every_object(r, bucket, name) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    tocm_s3_pattern_covers_objects(concat("", ["x", m[3]]), "x")
}

tf_covers_every_object(r, bucket, name) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    tocm_s3_pattern_covers_objects(r, sprintf("arn:%s:s3:::%s", [partitions[_], n]))
}

# Values that cannot be resolved statically are given the benefit of the doubt.
tf_covers_every_object(r, bucket, name) {
    not contains(r, "${")
    not literal_bucket_name(bucket)
}

tf_covers_every_object(r, bucket, name) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

tf_covers_every_object(r, bucket, name) {
    regex.match(`^(var|local|module|data)\.`, r)
}

document_has_restriction(ds, src, bucket, name) {
    r := ap_restrictions(ds, src.pol)[_]
    tf_covers_every_object(r.resources[_], bucket, name)
}

# A data block defined in several files must hold the restriction in each.
source_has_restriction(bucket, name, src) {
    count([ds | ds := source_documents(src)[_]; not document_has_restriction(ds, src, bucket, name)]) == 0
}

source_lacks_restriction(i, bucket, name) {
    src := bucket_policies(i, bucket, name)[_]
    not source_has_restriction(bucket, name, src)
}

# Only one of several policies applies, so each must hold the restriction alone.
has_restriction(i, bucket, name) {
    count(bucket_policies(i, bucket, name)) > 0
    not source_lacks_restriction(i, bucket, name)
}

multiple_sources(i, bucket, name) {
    count(bucket_policies(i, bucket, name)) > 1
}

allowed_aps(i, bucket, name) := {ap |
    ap := bucket_restrictions(i, bucket, name)[_].aps[_]
}

# --- Logic ---
# Fail 1: no access point restriction on the bucket at the required scope.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    not has_restriction(i, bucket, name)
    not multiple_sources(i, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny for all principals and all S3 actions on every object whose only condition is StringNotEquals on s3:DataAccessPointArn, with no NotPrincipal, NotAction or NotResource, listing only authorized access points: %v", [name, authorized_access_points]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy (policy argument or aws_s3_bucket_policy) restricting access to authorized access points at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Fail 1b: one of several bucket policies lacks the restriction.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    not has_restriction(i, bucket, name)
    multiple_sources(i, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("each bucket policy of bucket '%s' (policy argument and every aws_s3_bucket_policy) must hold a Deny for all principals and all S3 actions on every object whose only condition is StringNotEquals on s3:DataAccessPointArn, listing only authorized access points: %v", [name, authorized_access_points]),
        "keyActualValue": sprintf("bucket '%s' sets more than one bucket policy and only one applies after apply; not every one restricts access to authorized access points at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Fail 2: a restriction exists but allows an access point outside the set.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    unauth := allowed_aps(i, bucket, name) - authorized_access_points
    count(unauth) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must only allow authorized access points: %v", [name, authorized_access_points]),
        "keyActualValue": sprintf("bucket '%s' policy allows unauthorized access point(s): %v", [name, unauth]),
        "resourceTags": terraLib.get_resource_tags(bucket),
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
