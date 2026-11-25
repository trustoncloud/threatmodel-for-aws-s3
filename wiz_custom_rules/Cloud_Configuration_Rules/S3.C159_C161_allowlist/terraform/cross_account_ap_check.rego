package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher. Bucket names (or ARNs) and the accounts
# authorized to own them.
authorized_buckets := {
    "authorized-bucket",
}
authorized_accounts := {
    "123456789012",
}

# --- Logic ---
literal(v) {
    is_string(v)
    v != ""
    not tocm_tf_unresolved(v)
}

# A reference to aws_s3_bucket.<name> or data.aws_s3_bucket.<name> in this file.
bucket_reference(v) := {"block": m[1], "name": m[2]} {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*(data\.)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket|arn)\s*\}?\s*$`, v, 1)[0]
}

referenced_bucket(document, ref) := document.resource.aws_s3_bucket[ref.name] { ref.block == "" }
referenced_bucket(document, ref) := document.data.aws_s3_bucket[ref.name] { ref.block == "data." }

# The stated bucket name, or the name stated on the referenced bucket.
tf_target_bucket(document, ap) := ap.bucket {
    literal(ap.bucket)
    not bucket_reference(ap.bucket)
}

tf_target_bucket(document, ap) := n {
    n := referenced_bucket(document, bucket_reference(ap.bucket)).bucket
    literal(n)
}

# The bucket owner: bucket_account_id, else account_id. An access point that
# states neither is never approved.
stated(ap, key) { object.get(ap, key, null) != null }

stated_account(ap) := sprintf("%v", [ap.bucket_account_id]) { stated(ap, "bucket_account_id") }

stated_account(ap) := sprintf("%v", [ap.account_id]) {
    not stated(ap, "bucket_account_id")
    stated(ap, "account_id")
}

tf_target_account(ap) := a {
    a := stated_account(ap)
    regex.match(`^[0-9]{12}$`, a)
}

ap_authorized(document, ap) {
    authorized_buckets[tf_target_bucket(document, ap)]
    authorized_accounts[tf_target_account(ap)]
}

# --- Finding text ---
bucket_text(document, ap) := sprintf("bucket '%v'", [tf_target_bucket(document, ap)]) {
    tf_target_bucket(document, ap)
} else := sprintf("a bucket whose name is not resolved by this source scan ('%v')", [object.get(ap, "bucket", "")])

account_text(ap) := sprintf("account '%v'", [tf_target_account(ap)]) {
    tf_target_account(ap)
} else := sprintf("an account not resolved by this source scan to a 12-digit account ID ('%v')", [stated_account(ap)]) {
    stated_account(ap)
} else := "an account the access point does not state (set bucket_account_id or account_id)"

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

WizPolicy[result] {
    document := input.document[i]
    ap := document.resource.aws_s3_access_point[name]
    not tf_not_created(ap)
    not ap_authorized(document, ap)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_access_point",
        "resourceName": terraLib.get_resource_name(ap, name),
        "searchKey": sprintf("aws_s3_access_point[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("access point '%s' must target an authorized bucket (%v) and state an authorized owner account (%v) in bucket_account_id or account_id", [name, authorized_buckets, authorized_accounts]),
        "keyActualValue": sprintf("access point '%s' targets %s owned by %s", [name, bucket_text(document, ap), account_text(ap)]),
        "resourceTags": terraLib.get_resource_tags(ap),
    }
}

# --- Matching helpers ---
# --- toc-match begin: tf v1 ---
# A Terraform value that is still an unresolved reference ("${...}"). Treat
# it as unknown: never compare it with an allowlist as a string.
tocm_tf_unresolved(v) {
    is_string(v)
    contains(v, "${")
}
# --- toc-match end: tf v1 ---
