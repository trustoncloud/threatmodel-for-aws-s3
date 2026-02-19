package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Get Access Point Properties
ap_props := props {
    input.properties != null
    props := input.properties
}

# Helper: Get Parameters (Allowlists)
authorized_buckets := input.parameters.authorized_buckets
authorized_accounts := input.parameters.authorized_accounts

# Helper: Get Target Bucket Name
target_bucket := ap_props.bucket

# Helper: Get Target Account ID
# If bucketAccountId is explicitly set (Cross-Account/MRAP), use it.
# Otherwise, default to the resource's own account ID (Local AP).
target_account := account_id {
    ap_props.bucketAccountId != null
    account_id := ap_props.bucketAccountId
} else := account_id {
    account_id := input.accountId
}

# --- Validation Logic ---

# Check 1: Is the Bucket Name authorized?
is_bucket_authorized {
    authorized_buckets[_] == target_bucket
}

# Check 2: Is the Account ID authorized?
is_account_authorized {
    authorized_accounts[_] == target_account
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if properties are missing (Cannot validate)
    not ap_props
} else := "fail" {
    # Fail if the bucket name is not in the allowlist
    not is_bucket_authorized
} else := "fail" {
    # Fail if the bucket's account ID is not in the allowlist
    not is_account_authorized
}

# --- Metadata ---
currentConfiguration := sprintf("Access Point targets bucket '%v' in account '%v'.", [target_bucket, target_account])

expectedConfiguration := "Access Point must target a bucket listed in 'authorized_buckets' owned by an account in 'authorized_accounts'."