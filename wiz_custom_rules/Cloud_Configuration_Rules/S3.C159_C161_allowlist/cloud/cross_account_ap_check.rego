package wiz

# --- Configuration ---
authorized_buckets := {
    "authorized-bucket",
}
authorized_accounts := {
    "123456789012",
}

# --- Logic ---
default result := "pass"

has_ap {
    input.AccessPointArn != null
}

target_bucket := input.Bucket

# The bucket's owning account: BucketAccountId when set (cross-account access
# point), otherwise the access point's own account, parsed from its ARN
# (arn:aws:s3:<region>:<account>:accesspoint/<name>).
target_account := acct {
    input.BucketAccountId != null
    acct := input.BucketAccountId
} else := acct {
    acct := split(input.AccessPointArn, ":")[4]
}

bucket_authorized {
    authorized_buckets[target_bucket]
}

account_authorized {
    authorized_accounts[target_account]
}

result := "skip" {
    not has_ap
} else := "fail" {
    not bucket_authorized
} else := "fail" {
    not account_authorized
}

# --- Metadata ---
currentConfiguration := sprintf("Access point targets bucket '%v' in account '%v'.", [target_bucket, target_account])

expectedConfiguration := sprintf("Access point must target an authorized bucket (%v) owned by an authorized account (%v).", [authorized_buckets, authorized_accounts])
