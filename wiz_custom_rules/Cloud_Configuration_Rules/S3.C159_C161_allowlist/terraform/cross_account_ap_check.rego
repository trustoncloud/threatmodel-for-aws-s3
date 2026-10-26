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
is_reference(v) { contains(v, "${") }

# Literal bucket name: exact match against the authorized set.
tf_bucket_authorized(document, ap) {
    not is_reference(ap.bucket)
    authorized_buckets[ap.bucket]
}

# Reference to a bucket resource: resolve it and match its actual bucket
# name (falling back to the local resource name) exactly.
tf_bucket_authorized(document, ap) {
    is_reference(ap.bucket)
    ref := document.resource.aws_s3_bucket[bname]
    contains(ap.bucket, bname)
    real_name := object.get(ref, "bucket", bname)
    authorized_buckets[real_name]
}

# The bucket's owning account: bucket_account_id (cross-account) when set,
# otherwise account_id (the access point owner). Undefined when neither is
# declared, in which case the account cannot be evaluated.
resolved_account(ap) := ap.bucket_account_id { ap.bucket_account_id }
resolved_account(ap) := ap.account_id {
    not ap.bucket_account_id
    ap.account_id
}

account_ok(ap) { not resolved_account(ap) }
account_ok(ap) { authorized_accounts[resolved_account(ap)] }

ap_authorized(document, ap) {
    tf_bucket_authorized(document, ap)
    account_ok(ap)
}

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
        "keyExpectedValue": sprintf("access point '%s' must target an authorized bucket (%v) owned by an authorized account (%v)", [name, authorized_buckets, authorized_accounts]),
        "keyActualValue": sprintf("access point '%s' targets bucket '%v' owned by account '%v'", [name, ap.bucket, object.get(ap, "bucket_account_id", object.get(ap, "account_id", "unknown"))]),
        "resourceTags": terraLib.get_resource_tags(ap),
    }
}
