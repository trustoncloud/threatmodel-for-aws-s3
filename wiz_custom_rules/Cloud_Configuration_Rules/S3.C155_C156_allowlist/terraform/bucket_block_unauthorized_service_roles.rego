package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Roles a bucket policy Deny may exempt, by full ARN; keep in sync with the
# cloud matcher. Each is authorized on every bucket, so list only the
# service-linked roles they need (such as Amazon Macie). List every exempt role.
authorized_service_roles := {
    "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
}

# --- Policy helpers ---
# A policy arrives as IAM JSON, as JSON with data-source keys (Actions,
# Resources, Principals), or as an aws_iam_policy_document block.

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

# --- Service-linked roles ---
# A like value counts only if it reaches every service-linked role in a
# partition: any account, and all of role/aws-service-role/ or a form below.
slr_resource_forms := {
    "*/AWSServiceRoleFor*",
    "*AWSServiceRoleFor*",
    "role/*/AWSServiceRoleFor*",
    "role/*AWSServiceRoleFor*",
    "role/aws-service-role/*/AWSServiceRoleFor*",
    "role/aws-service-role/*AWSServiceRoleFor*",
}

slr_resource_covered(r) {
    tocm_iam_pattern_covers_prefix(r, "role/aws-service-role/")
}

slr_resource_covered(r) {
    slr_resource_forms[r]
}

# The source does not show the bucket's partition, so any one of these counts.
partitions := {"aws", "aws-cn", "aws-us-gov"}

# Operators naming the roles the Deny applies to. ArnEquals acts as ArnLike.
# Operator names match exactly.
like_operators := {"ArnLike", "ArnLikeIfExists", "ArnEquals", "ArnEqualsIfExists", "StringLike", "StringLikeIfExists"}

arn_operators := {"ArnLike", "ArnLikeIfExists", "ArnEquals", "ArnEqualsIfExists"}

# Operators that exempt roles from the Deny.
exempt_operators := {
    "ArnNotEquals", "ArnNotEqualsIfExists", "ArnNotLike", "ArnNotLikeIfExists",
    "StringNotEquals", "StringNotEqualsIfExists", "StringNotLike", "StringNotLikeIfExists",
}

# An account ID has twelve digits. A part of "?" and "*" covers every ID with
# exactly twelve "?", or with at most twelve "?" and a "*".
account_covers_all(a) {
    is_string(a)
    regex.match(`^[?]{12}$`, a)
}

account_covers_all(a) {
    is_string(a)
    regex.match(`^[?*]+$`, a)
    contains(a, "*")
    count(replace(a, "*", "")) <= 12
}

# ArnLike and ArnEquals compare the six ARN parts one by one.
like_value_covers_slrs(op, v, partition) {
    arn_operators[op]
    p := tocm_arn_parts(v)
    {partition, "*"}[p.partition]
    {"iam", "*"}[p.service]
    {"", "*"}[p.region]
    account_covers_all(p.account)
    slr_resource_covered(p.resource)
}

# StringLike reads the whole value, where "*" also spans ":".
like_value_covers_slrs(op, v, partition) {
    not arn_operators[op]
    tocm_iam_pattern_covers_prefix(v, concat("", ["arn:", partition, ":iam::"]))
}

like_value_covers_slrs(op, v, partition) {
    not arn_operators[op]
    is_string(v)
    part := {partition, "*"}[_]
    prefix := concat("", ["arn:", part, ":iam::"])
    startswith(v, prefix)
    rest := substring(v, count(prefix), -1)
    i := indexof(rest, ":")
    i > 0
    account_covers_all(substring(rest, 0, i))
    slr_resource_covered(substring(rest, i + 1, -1))
}

# JSON statements: Condition is {operator: {key: value}}.
json_arn_values(stmt, operator) := vals {
    conditions := stmt.Condition[operator]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == "aws:principalarn"
    vals := terraLib.getArray(val)
}

json_principal_arn_operator(stmt, operator) {
    like_operators[operator]
    json_arn_values(stmt, operator)
}

json_principal_arn_operator(stmt, operator) {
    exempt_operators[operator]
    json_arn_values(stmt, operator)
}

json_has_other_condition(stmt) {
    stmt.Condition[operator]
    not json_principal_arn_operator(stmt, operator)
}

json_operator_covers(stmt, operator, partition) {
    p := json_arn_values(stmt, operator)[_]
    like_value_covers_slrs(operator, p, partition)
}

# Like operators combine with AND, so each must reach every role.
json_misses_some_slr(stmt, partition) {
    stmt.Condition[operator]
    like_operators[operator]
    not json_operator_covers(stmt, operator, partition)
}

json_blocks(stmt) {
    stmt.Effect == "Deny"
    not json_uses_not(stmt)
    json_covers_all_s3(stmt)
    json_everyone(stmt)
    not json_has_other_condition(stmt)
    partition := partitions[_]
    not json_misses_some_slr(stmt, partition)
}

json_exemptions(stmt) := {v |
    stmt.Condition[operator]
    exempt_operators[operator]
    v := json_arn_values(stmt, operator)[_]
}

# Data-source statements: each condition holds one test, variable and values.
hcl_principal_arn_condition(c) {
    lower(c.variable) == "aws:principalarn"
    like_operators[c.test]
}

hcl_principal_arn_condition(c) {
    lower(c.variable) == "aws:principalarn"
    exempt_operators[c.test]
}

hcl_has_other_condition(stmt) {
    c := terraLib.getArray(stmt.condition)[_]
    not hcl_principal_arn_condition(c)
}

hcl_test_covers(stmt, test, partition) {
    c := terraLib.getArray(stmt.condition)[_]
    c.test == test
    p := terraLib.getArray(c.values)[_]
    like_value_covers_slrs(test, p, partition)
}

hcl_misses_some_slr(stmt, partition) {
    c := terraLib.getArray(stmt.condition)[_]
    like_operators[c.test]
    not hcl_test_covers(stmt, c.test, partition)
}

hcl_blocks(stmt) {
    lower(stmt.effect) == "deny"
    not hcl_uses_not(stmt)
    hcl_covers_all_s3(stmt)
    hcl_everyone(stmt)
    not hcl_has_other_condition(stmt)
    partition := partitions[_]
    not hcl_misses_some_slr(stmt, partition)
}

hcl_exemptions(stmt) := {v |
    c := terraLib.getArray(stmt.condition)[_]
    exempt_operators[c.test]
    v := terraLib.getArray(c.values)[_]
}

# With no like operator, the Deny reaches every principal it does not exempt.
# Read from the JSON and from data block ds ({} if none).
role_restrictions(ds, pol) := json_rs | hcl_rs {
    json_rs := {{"resources": stmt_resources(stmt), "roles": json_exemptions(stmt)} |
        stmt := json_statements(pol)[_]
        json_blocks(stmt)
    }
    hcl_rs := {{"resources": terraLib.getArray(stmt.resources), "roles": hcl_exemptions(stmt)} |
        stmt := tf_deny_statements(ds)[_]
        hcl_blocks(stmt)
    }
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

# The data blocks a source names, each read on its own.
source_documents(src) := tf_documents_or_none(src.doc, object.get(src.pol, "policy", null))

# An unauthorized exemption in any data block a source names is reported.
bucket_restrictions(i, bucket, name) := {r |
    src := bucket_policies(i, bucket, name)[_]
    ds := source_documents(src)[_]
    r := role_restrictions(ds, src.pol)[_]
}

# --- Resource scope ---
# The deny must reach the bucket itself and every object in it.
scope_targets := {"bucket", "objects"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

# A pattern reaches the objects only when it leaves no key out.
pattern_reaches(pattern, arn, "bucket") {
    tocm_iam_pattern_matches(pattern, arn)
}

pattern_reaches(pattern, arn, "objects") {
    tocm_s3_pattern_covers_objects(pattern, arn)
}

resource_reaches(r, bucket, name, target) {
    r == "*"
}

# A reference to this bucket's ARN or name: "x" stands in for the bucket ARN.
resource_reaches(r, bucket, name, target) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    pattern_reaches(concat("", ["x", m[3]]), "x", target)
}

resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    pattern_reaches(r, sprintf("arn:%s:s3:::%s", [partitions[_], n]), target)
}

# A resource that cannot be resolved statically gets the benefit of the doubt.
resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    not literal_bucket_name(bucket)
}

resource_reaches(r, bucket, name, target) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

resource_reaches(r, bucket, name, target) {
    regex.match(`^(var|local|module|data)\.`, r)
}

document_has_restriction(ds, src, bucket, name) {
    reached := {target |
        r := role_restrictions(ds, src.pol)[_]
        scope_targets[target]
        resource_reaches(r.resources[_], bucket, name, target)
    }
    count(reached) == count(scope_targets)
}

# A data block defined in several files must hold the Deny in each.
source_has_restriction(bucket, name, src) {
    count([ds | ds := source_documents(src)[_]; not document_has_restriction(ds, src, bucket, name)]) == 0
}

source_lacks_restriction(i, bucket, name) {
    src := bucket_policies(i, bucket, name)[_]
    not source_has_restriction(bucket, name, src)
}

# Only one policy holds after apply, so each must hold the Deny on its own.
has_restriction(i, bucket, name) {
    count(bucket_policies(i, bucket, name)) > 0
    not source_lacks_restriction(i, bucket, name)
}

multiple_sources(i, bucket, name) {
    count(bucket_policies(i, bucket, name)) > 1
}

unauthorized_exemptions(i, bucket, name) := {role |
    role := bucket_restrictions(i, bucket, name)[_].roles[_]
    not tocm_arn_allowed(role, authorized_service_roles)
}

# --- Logic ---
# Fail 1: no Deny reaching every service-linked role at the required scope.
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
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny for all principals and all S3 actions on the bucket and every object in it that reaches every service-linked role, with aws:PrincipalArn as its only condition key: an ArnLike or StringLike pattern matching every account that covers every role under role/aws-service-role/ or named AWSServiceRoleFor (such as arn:aws:iam::*:role/aws-service-role/*), or no pattern so the Deny reaches every principal, exempting only authorized roles: %v", [name, authorized_service_roles]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy (policy argument or aws_s3_bucket_policy) Deny that reaches every service-linked role at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Fail 1b: the bucket sets more than one policy and not every one holds the Deny.
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
        "keyExpectedValue": sprintf("each bucket policy of bucket '%s' (policy argument and every aws_s3_bucket_policy) must hold a Deny for all principals and all S3 actions on the bucket and every object in it that reaches every service-linked role, exempting only authorized roles: %v", [name, authorized_service_roles]),
        "keyActualValue": sprintf("bucket '%s' sets more than one bucket policy and only one applies after apply; not every one holds a Deny that reaches every service-linked role at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Fail 2: a Deny exists but exempts a role outside the authorized set.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not tf_not_created(bucket)
    unauth := unauthorized_exemptions(i, bucket, name)
    count(unauth) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must only exempt authorized service roles: %v", [name, authorized_service_roles]),
        "keyActualValue": sprintf("bucket '%s' policy exempts unauthorized role(s): %v", [name, unauth]),
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
