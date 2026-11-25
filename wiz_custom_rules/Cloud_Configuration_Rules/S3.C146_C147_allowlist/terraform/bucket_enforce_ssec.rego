package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Buckets that must enforce SSE-C on PutObject: a bucket name for the whole
# bucket, or "bucket/prefix/" for one path inside it. Keep in sync with the
# cloud matcher.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
}

# --- Policy helpers ---
# A policy arrives as IAM JSON, as JSON with data-source keys (Actions,
# Resources, Principals), or as an aws_iam_policy_document block.

stmt_actions(stmt) := terraLib.getArray(stmt.Action)
stmt_actions(stmt) := terraLib.getArray(stmt.Actions)

stmt_resources(stmt) := terraLib.getArray(stmt.Resource)
stmt_resources(stmt) := terraLib.getArray(stmt.Resources)

# Actions compare in lower case. A pattern counts only if it matches s3:PutObject.
tf_covers_put_object(actions) { tocm_iam_pattern_matches(lower(actions[_]), "s3:putobject") }

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

value_is(v, target) { v == target }
value_is(v, target) { v[_] == target }

ssec_key := "s3:x-amz-server-side-encryption-customer-algorithm"

# The SSE-C test must be the only condition. Operator names match exactly.
enforcing_test(operator, key, values) {
    {"StringNotEquals", "StringNotEqualsIfExists"}[operator]
    lower(key) == ssec_key
    value_is(values, "AES256")
}

enforcing_test(operator, key, values) {
    operator == "Null"
    lower(key) == ssec_key
    value_is(values, "true")
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

# A Deny written with NotResource, NotAction or NotPrincipal never counts.
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

# Resources of each enforcing Deny in the JSON and in data block ds ({} if none).
ssec_deny_resources(ds, pol) := json_rs | hcl_rs {
    json_rs := {r |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        not json_uses_not(stmt)
        tf_covers_put_object(stmt_actions(stmt))
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        count(conditions) == 1
        val := conditions[key]
        enforcing_test(operator, key, val)
        r := stmt_resources(stmt)[_]
    }
    hcl_rs := {r |
        stmt := tf_deny_statements(ds)[_]
        lower(stmt.effect) == "deny"
        not hcl_uses_not(stmt)
        tf_covers_put_object(terraLib.getArray(stmt.actions))
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        enforcing_test(conds[0].test, conds[0].variable, conds[0].values)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Required paths ---
# The bucket name is the `bucket` argument, falling back to the local name.
bucket_name(bucket, name) := object.get(bucket, "bucket", name)

# Paths of a bucket that require SSE-C; "" stands for the whole bucket.
tf_required_prefixes(bname) := whole | paths {
    whole := {"" | buckets_requiring_ssec[bname]}
    paths := {prefix |
        entry := buckets_requiring_ssec[_]
        startswith(entry, concat("", [bname, "/"]))
        path := trim_suffix(trim_prefix(entry, concat("", [bname, "/"])), "/")
        path != ""
        prefix := concat("", [path, "/"])
    }
}

# --- Resource scope ---
# The deny must reach every key under the required path; "" is the whole bucket.
partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

reaches_path(r, bucket, name, prefix) {
    r == "*"
}

# A reference to this bucket's ARN or name: "x" stands in for the bucket ARN.
reaches_path(r, bucket, name, prefix) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    tf_covers_path(concat("", ["x", m[3]]), "x", prefix)
}

reaches_path(r, bucket, name, prefix) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    tf_covers_path(r, sprintf("arn:%s:s3:::%s", [partitions[_], n]), prefix)
}

# "/?*" covers a whole bucket, since a key is never empty. A path needs "*":
# the key that names the path is an object too.
tf_covers_path(p, bucket_arn, prefix) {
    prefix == ""
    tocm_s3_pattern_covers_objects(p, bucket_arn)
}

tf_covers_path(p, bucket_arn, prefix) {
    prefix != ""
    tocm_iam_pattern_covers_prefix(p, concat("", [bucket_arn, "/", prefix]))
}

# A resource that cannot be resolved statically gets the benefit of the doubt.
reaches_path(r, bucket, name, prefix) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

reaches_path(r, bucket, name, prefix) {
    regex.match(`^(var|local|module|data)\.`, r)
}

# The policy argument and every linked aws_s3_bucket_policy. Only one holds
# after apply, so each must enforce every required path on its own.
bucket_policies(i, bucket, name) := inline | linked {
    inline := {src |
        is_string(object.get(bucket, "policy", null))
        src := {"id": sprintf("aws_s3_bucket.%s (policy argument)", [name]), "doc": i, "pol": bucket}
    }
    linked := {{"id": sprintf("aws_s3_bucket_policy.%s", [pName]), "doc": j, "pol": pol} |
        pol := input.document[j].resource.aws_s3_bucket_policy[pName]
        not tf_not_created(pol)
        terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
        tf_reference_reaches(i, j, pol.bucket, "aws_s3_bucket", name)
    }
}

document_enforces(ds, src, bucket, name, prefix) {
    reaches_path(ssec_deny_resources(ds, src.pol)[_], bucket, name, prefix)
}

# A data block defined in several files must enforce the path in each.
source_enforces(src, bucket, name, prefix) {
    docs := tf_documents_or_none(src.doc, object.get(src.pol, "policy", null))
    count([ds | ds := docs[_]; not document_enforces(ds, src, bucket, name, prefix)]) == 0
}

# Required paths that some source leaves unenforced; with no source, all of them.
tf_missing_prefixes(i, bucket, name, required) := required {
    count(bucket_policies(i, bucket, name)) == 0
} else := {prefix |
    src := bucket_policies(i, bucket, name)[_]
    prefix := required[_]
    not source_enforces(src, bucket, name, prefix)
}

sources_without_ssec(i, bucket, name, required) := {src.id |
    src := bucket_policies(i, bucket, name)[_]
    prefix := required[_]
    not source_enforces(src, bucket, name, prefix)
}

ssec_actual_value(i, bucket, name, bname, required, labels) := sprintf("bucket '%s' sets more than one bucket policy and only one applies after apply, so each must enforce SSE-C on %s on its own; these do not: %s", [bname, labels, concat(", ", sort(sources_without_ssec(i, bucket, name, required)))]) {
    count(bucket_policies(i, bucket, name)) > 1
} else := sprintf("bucket '%s' has no bucket policy (policy argument or aws_s3_bucket_policy) enforcing SSE-C on %s", [bname, labels])

path_label(prefix) := "the whole bucket" { prefix == "" } else := prefix

# --- Logic ---
# Only buckets with a required path are checked.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    bname := bucket_name(bucket, name)
    required := tf_required_prefixes(bname)
    count(required) > 0
    missing := tf_missing_prefixes(i, bucket, name, required)
    count(missing) > 0
    labels := concat(", ", sort([path_label(p) | p := missing[_]]))

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' requires SSE-C on %s and must have a bucket policy denying s3:PutObject there for all principals when the customer-algorithm header is missing or not AES256, with no other condition", [bname, labels]),
        "keyActualValue": ssec_actual_value(i, bucket, name, bname, required, labels),
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
