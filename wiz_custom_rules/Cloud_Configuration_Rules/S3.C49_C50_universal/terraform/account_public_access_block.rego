package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Block Public Access flags; each defaults to false, so an omitted flag fails.
required_flags := {
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
}

# --- Logic ---
# --- toc-match begin: tf v1 ---
# A Terraform value that is still an unresolved reference ("${...}"). Treat
# it as unknown: never compare it with an allowlist as a string.
tocm_tf_unresolved(v) {
    is_string(v)
    contains(v, "${")
}
# --- toc-match end: tf v1 ---

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

# HCL reads "true", "1", "false" and "0" as bools; a reference is undefined.
tf_bool(v) := v {
    is_boolean(v)
}

tf_bool(v) := true {
    v == "true"
}

tf_bool(v) := true {
    v == "1"
}

tf_bool(v) := false {
    v == "false"
}

tf_bool(v) := false {
    v == "0"
}

# One finding per false or missing flag; a flag set by reference is not judged.
WizPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_s3_account_public_access_block[name]
    not tf_not_created(resource)
    flag := required_flags[_]
    value := object.get(resource, flag, false)
    not tocm_tf_unresolved(value)
    not tf_bool(value) == true

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_account_public_access_block",
        "resourceName": terraLib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_s3_account_public_access_block[%s].%s", [name, flag]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("%s must be true", [flag]),
        "keyActualValue": sprintf("%s is false or not set (provider default is false)", [flag]),
        "resourceTags": terraLib.get_resource_tags(resource),
    }
}
