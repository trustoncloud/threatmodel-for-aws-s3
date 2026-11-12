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
# Policies reach the matcher in three shapes: a JSON string with real IAM keys
# (jsonencode or heredoc), a JSON string with resolved data-source keys
# (Actions/Resources/Principals, condition values as arrays), or an unresolved
# reference to an aws_iam_policy_document data block (walked directly,
# lowercase names).

stmt_actions(stmt) := terraLib.getArray(stmt.Action)
stmt_actions(stmt) := terraLib.getArray(stmt.Actions)

stmt_resources(stmt) := terraLib.getArray(stmt.Resource)
stmt_resources(stmt) := terraLib.getArray(stmt.Resources)

put_object_actions := {"s3:PutObject", "s3:*", "*"}

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

# The SSE-C test must be the only condition: a StringNotEquals AES256 or a
# Null true on the customer-algorithm header.
enforcing_test(operator, key, values) {
    {"stringnotequals", "stringnotequalsifexists"}[lower(operator)]
    lower(key) == ssec_key
    value_is(values, "AES256")
}

enforcing_test(operator, key, values) {
    lower(operator) == "null"
    lower(key) == ssec_key
    value_is(values, "true")
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

# A statement written with NotResource, NotAction or NotPrincipal is never
# counted as the covering deny.
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

# Resources of every Deny on PutObject for everyone that enforces SSE-C.
ssec_deny_resources(document, pol) := json_rs | hcl_rs {
    json_rs := {r |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        not json_uses_not(stmt)
        put_object_actions[stmt_actions(stmt)[_]]
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        count(conditions) == 1
        val := conditions[key]
        enforcing_test(operator, key, val)
        r := stmt_resources(stmt)[_]
    }
    hcl_rs := {r |
        is_string(pol.policy)
        ds := document.data.aws_iam_policy_document[policy_data_source_name(pol.policy)]
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        not hcl_uses_not(stmt)
        put_object_actions[terraLib.getArray(stmt.actions)[_]]
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

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it, with "x" standing for the bucket ARN.
reaches_path(r, bucket, name, prefix) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    tf_covers_path(concat("", ["x", m[3]]), "x", prefix)
}

reaches_path(r, bucket, name, prefix) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    tf_covers_path(r, sprintf("arn:%s:s3:::%s", [partitions[_], n]), prefix)
}

# The whole bucket: an object key is never empty, so "/?*" reaches every
# object. A path stays strict: the key that names the path is an object too.
tf_covers_path(p, bucket_arn, prefix) {
    prefix == ""
    tocm_s3_pattern_covers_objects(p, bucket_arn)
}

tf_covers_path(p, bucket_arn, prefix) {
    prefix != ""
    tocm_iam_pattern_covers_prefix(p, concat("", [bucket_arn, "/", prefix]))
}

# Values that cannot be resolved statically (variables, locals, module
# outputs) are given the benefit of the doubt.
reaches_path(r, bucket, name, prefix) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

reaches_path(r, bucket, name, prefix) {
    regex.match(`^(var|local|module|data)\.`, r)
}

tf_enforced_prefixes(document, bucket, name, required) := {prefix |
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    r := ssec_deny_resources(document, pol)[_]
    prefix := required[_]
    reaches_path(r, bucket, name, prefix)
}

path_label(prefix) := "the whole bucket" { prefix == "" } else := prefix

# --- Logic ---
# Only buckets with a required path are checked.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    bname := bucket_name(bucket, name)
    required := tf_required_prefixes(bname)
    count(required) > 0
    missing := required - tf_enforced_prefixes(document, bucket, name, required)
    count(missing) > 0
    labels := concat(", ", sort([path_label(p) | p := missing[_]]))

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' requires SSE-C on %s and must have a bucket policy denying s3:PutObject there for all principals when the customer-algorithm header is missing or not AES256, with no other condition", [bname, labels]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy enforcing SSE-C on %s", [bname, labels]),
        "resourceTags": terraLib.get_resource_tags(bucket),
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
