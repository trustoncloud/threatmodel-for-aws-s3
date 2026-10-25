package wiz

# --- Configuration ---
# Regions where S3 offers no account regional namespace; buckets there are not
# judged. Keep in sync with the Terraform matcher.
unsupported_regions := {"me-south-1", "me-central-1"}

# --- Logic ---
default result := "pass"

account_id := a {
    a := input.WizMetadata.accountId
    is_string(a)
    regex.match(`^[0-9]{12}$`, a)
}

# BucketRegion comes from ListBuckets; the connector's own region field is the
# fallback.
region := r {
    r := input.BucketRegion
    is_string(r)
    r != ""
} else := r {
    r := input.WizMetadata.region
    is_string(r)
    r != ""
}

# No API returns a bucket's namespace. S3 reserves the -an ending for account
# regional buckets, named <prefix>-<account id>-<region>-an.
expected_suffix := sprintf("-%s-%s-an", [account_id, region])

in_account_regional_namespace {
    endswith(input.Name, expected_suffix)
}

result := "skip" {
    not is_string(input.Name)
} else := "skip" {
    not account_id
} else := "skip" {
    not region
} else := "skip" {
    unsupported_regions[region]
} else := "fail" {
    not in_account_regional_namespace
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket '%s' is in the global namespace: its name does not end with '%s'.", [input.Name, expected_suffix]) {
    result == "fail"
} else := "Bucket is in its account regional namespace."

expectedConfiguration := "Every general purpose bucket must be created in its account regional namespace (CreateBucket with x-amz-bucket-namespace: account-regional), named <prefix>-<account id>-<region>-an, so no other account can ever re-create its name."
