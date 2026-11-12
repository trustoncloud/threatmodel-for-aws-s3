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

# A reference to a bucket in this file, by its exact address: a managed
# bucket (aws_s3_bucket.<name>) or a data source (data.aws_s3_bucket.<name>),
# through its id, bucket or arn.
bucket_reference(v) := {"block": m[1], "name": m[2]} {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*(data\.)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket|arn)\s*\}?\s*$`, v, 1)[0]
}

referenced_bucket(document, ref) := document.resource.aws_s3_bucket[ref.name] { ref.block == "" }
referenced_bucket(document, ref) := document.data.aws_s3_bucket[ref.name] { ref.block == "data." }

# The bucket name an access point targets: the name it states, or the name
# stated on the bucket it references. A generated name is not in the source.
tf_target_bucket(document, ap) := ap.bucket {
    literal(ap.bucket)
    not bucket_reference(ap.bucket)
}

tf_target_bucket(document, ap) := n {
    n := referenced_bucket(document, bucket_reference(ap.bucket)).bucket
    literal(n)
}

# The account that owns the bucket: bucket_account_id when the access point
# states it, otherwise account_id, the owner of the access point. An access
# point that states neither is never approved.
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

WizPolicy[result] {
    document := input.document[i]
    ap := document.resource.aws_s3_access_point[name]
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
