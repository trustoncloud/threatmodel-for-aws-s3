package wiz

# --- Configuration ---
# Buckets that must enforce SSE-C on PutObject: a bucket name for the whole
# bucket, or "bucket/prefix/" for one path inside it.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
}

# --- Logic ---
default result := "pass"

policy_doc := doc {
    is_string(input.bucketPolicy)
    doc := json.unmarshal(input.bucketPolicy)
} else := doc {
    is_object(input.bucketPolicy)
    doc := input.bucketPolicy
}

fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketPolicy.result == "Success"
}

# Paths of this bucket that require SSE-C; "" stands for the whole bucket.
required_prefixes[prefix] {
    buckets_requiring_ssec[input.Name]
    prefix := ""
}

required_prefixes[prefix] {
    entry := buckets_requiring_ssec[_]
    startswith(entry, concat("", [input.Name, "/"]))
    path := trim_suffix(trim_prefix(entry, concat("", [input.Name, "/"])), "/")
    path != ""
    prefix := concat("", [path, "/"])
}

is_required_bucket {
    count(required_prefixes) > 0
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

covers_put_object(action) { action == "s3:PutObject" }
covers_put_object(action) { action == "s3:*" }
covers_put_object(action) { action == "*" }
covers_put_object(action) { action[_] == "s3:PutObject" }
covers_put_object(action) { action[_] == "s3:*" }
covers_put_object(action) { action[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

applies_to_everyone(principal) { principal == "*" }
applies_to_everyone(principal) { wildcard(principal.AWS) }

value_is(v, target) { v == target }
value_is(v, target) { v[_] == target }

bucket_arn := input.BucketArn {
    is_string(input.BucketArn)
} else := sprintf("arn:aws:s3:::%s", [input.Name])

# A sample object under the required path stands in for any key there.
sample_object(prefix) := sprintf("%s/%ssample-object", [bucket_arn, prefix])

as_array(v) := v { is_array(v) } else := [v]

ssec_key := "s3:x-amz-server-side-encryption-customer-algorithm"

# The SSE-C test must be the only condition: a StringNotEquals AES256 or a
# Null true on the customer-algorithm header.
enforcing_condition(stmt) {
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    {"stringnotequals", "stringnotequalsifexists"}[lower(operator)]
    count(conditions) == 1
    val := conditions[key]
    lower(key) == ssec_key
    value_is(val, "AES256")
}

enforcing_condition(stmt) {
    count(stmt.Condition) == 1
    conditions := stmt.Condition[operator]
    lower(operator) == "null"
    count(conditions) == 1
    val := conditions[key]
    lower(key) == ssec_key
    value_is(val, "true")
}

enforced_prefixes[prefix] {
    stmt := statements[_]
    stmt.Effect == "Deny"
    covers_put_object(stmt.Action)
    applies_to_everyone(stmt.Principal)
    enforcing_condition(stmt)
    prefix := required_prefixes[_]
    glob.match(as_array(stmt.Resource)[_], [], sample_object(prefix))
}

missing_prefixes := required_prefixes - enforced_prefixes

result := "skip" {
    not fetch_ok
} else := "pass" {
    not is_required_bucket
} else := "fail" {
    count(missing_prefixes) > 0
}

# --- Metadata ---
path_label(prefix) := "the whole bucket" { prefix == "" } else := prefix

currentConfiguration := sprintf("Bucket requires SSE-C on %s but its policy does not enforce it there for all principals on PutObject, with no other condition.", [concat(", ", sort([path_label(p) | p := missing_prefixes[_]]))]) {
    result == "fail"
} else := "Bucket enforces SSE-C on its required paths, or is not required to."

expectedConfiguration := "Buckets and paths in the required set must Deny s3:PutObject for all principals when s3:x-amz-server-side-encryption-customer-algorithm is missing (Null true) or not AES256 (StringNotEquals), with no other condition."
