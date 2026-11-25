package wiz

# --- Logic ---
default result := "pass"

# The vpcEndpoint native type covers every service; only S3 endpoints count.
is_s3_endpoint {
    endswith(input.ServiceName, ".s3")
}

policy_doc := doc {
    is_string(input.PolicyDocument)
    doc := json.unmarshal(input.PolicyDocument)
} else := doc {
    is_object(input.PolicyDocument)
    doc := input.PolicyDocument
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

as_array(v) := v { is_array(v) } else := [v]

all_s3_actions := {"*", "s3:*"}

covers_all_actions(stmt) {
    all_s3_actions[lower(as_array(stmt.Action)[_])]
}

applies_to_everyone(stmt) { as_array(stmt.Principal)[_] == "*" }
applies_to_everyone(stmt) { as_array(stmt.Principal.AWS)[_] == "*" }

# The Deny must cover every bucket and object. The payload does not name its
# partition, so a pattern for any partition counts.
partitions := {"aws", "aws-cn", "aws-us-gov"}

covers_every_bucket_and_object(stmt) {
    tocm_s3_pattern_covers_all(as_array(stmt.Resource)[_], partitions[_])
}

# A statement with NotPrincipal, NotAction or NotResource never counts.
negated_elements := {"NotPrincipal", "NotAction", "NotResource"}

uses_negation(stmt) {
    negated_elements[k]
    object.get(stmt, k, null) != null
}

full_scope_deny(stmt) {
    stmt.Effect == "Deny"
    not uses_negation(stmt)
    applies_to_everyone(stmt)
    covers_all_actions(stmt)
    covers_every_bucket_and_object(stmt)
}

# Every condition test as {operator, key, values}. Operators match by exact
# name; condition key names are not case sensitive.
conditions(stmt) := [{"operator": op, "key": lower(key), "values": as_array(v)} | v := stmt.Condition[op][key]]

value_false(v) { v == "false" }
value_false(v) { v == false }

transport_test(c) {
    {"Bool", "BoolIfExists"}[c.operator]
    c.key == "aws:securetransport"
    value_false(c.values[_])
}

tls_test(c) {
    {"NumericLessThan", "NumericLessThanIfExists"}[c.operator]
    c.key == "s3:tlsversion"
    to_number(c.values[_]) >= 1.2
}

# A Deny may exempt AWS services with aws:PrincipalIsAWSService false. Only
# BoolIfExists keeps the Deny on anonymous requests, which omit that key.
service_exemption(c) {
    c.operator == "BoolIfExists"
    c.key == "aws:principalisawsservice"
    count(c.values) > 0
    count([v | v := c.values[_]; not value_false(v)]) == 0
}

protection_test(c, "transport") { transport_test(c) }
protection_test(c, "tls") { tls_test(c) }

# The transport test stands alone or beside the service exemption; any other
# key narrows the deny.
qualifying_conditions(stmt, kind) {
    cs := conditions(stmt)
    count(cs) == 1
    protection_test(cs[0], kind)
}

qualifying_conditions(stmt, kind) {
    cs := conditions(stmt)
    count(cs) == 2
    some i
    protection_test(cs[i], kind)
    service_exemption(cs[1 - i])
}

denies_insecure_transport(stmt) {
    full_scope_deny(stmt)
    qualifying_conditions(stmt, "transport")
}

denies_old_tls(stmt) {
    full_scope_deny(stmt)
    qualifying_conditions(stmt, "tls")
}

has_secure_transport_deny {
    denies_insecure_transport(statements[_])
}

has_tls_floor_deny {
    denies_old_tls(statements[_])
}

# Both Denies are required: a plain HTTP request carries no TLS version.
result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    not has_secure_transport_deny
} else := "fail" {
    not has_tls_floor_deny
}

# --- Metadata ---
missing_protections[p] {
    not has_secure_transport_deny
    p := "a Deny of unencrypted requests (aws:SecureTransport false)"
}

missing_protections[p] {
    not has_tls_floor_deny
    p := "a Deny of TLS versions below 1.2 (s3:TlsVersion)"
}

currentConfiguration := "VPC endpoint has no policy, so it does not deny unencrypted requests or old TLS versions." {
    result == "fail"
    input.PolicyDocument == null
} else := sprintf("VPC endpoint policy lacks %s. Each Deny must apply to all principals and all S3 actions on all buckets and objects, with no other condition than an optional aws:PrincipalIsAWSService false under BoolIfExists.", [concat(" and ", [p | p := missing_protections[_]])]) {
    result == "fail"
} else := "VPC endpoint policy denies unencrypted requests and TLS versions below 1.2 on all buckets and objects."

expectedConfiguration := "S3 VPC endpoint policy must contain a Deny for all principals and all S3 actions on all buckets and objects when aws:SecureTransport is false, and another when s3:TlsVersion is below 1.2. Each may exempt AWS service principals with aws:PrincipalIsAWSService false under BoolIfExists and must carry no other condition."

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
