package wiz

# --- Configuration ---
# Exact bucket name to its Object Lock default: mode, GOVERNANCE or
# COMPLIANCE in capitals, and min_days from your retention policy (a year is
# 365 days). Other buckets are not assessed.
worm_buckets := {
    "worm-records-bucket": {"mode": "COMPLIANCE", "min_days": 365},
    "worm-audit-bucket": {"mode": "GOVERNANCE", "min_days": 730},
}

# --- Logic ---
default result := "pass"

# Without Object Lock the configuration is null with a Success fetch status.
# The payload shows the default for new objects only, never stored objects.
fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketObjectLockConfiguration.result == "Success"
}

required := worm_buckets[input.Name]

lock := input.bucketObjectLockConfiguration.ObjectLockConfiguration

lock_enabled {
    lock.ObjectLockEnabled == "Enabled"
}

retention := r {
    r := lock.Rule.DefaultRetention
    is_object(r)
}

# Days and Years cannot both be set; a year counts 365 days.
retention_days := d {
    d := retention.Days
    is_number(d)
} else := d {
    is_number(retention.Years)
    d := retention.Years * 365
}

period_label := "1 day" {
    retention.Days == 1
} else := sprintf("%v days", [retention.Days]) {
    is_number(retention.Days)
} else := sprintf("1 year (%v days)", [retention_days]) {
    retention.Years == 1
} else := sprintf("%v years (%v days)", [retention.Years, retention_days]) {
    is_number(retention.Years)
}

problems[msg] {
    required
    not lock_enabled
    msg := sprintf("Bucket requires WORM but Object Lock is not enabled (expected %s for at least %v days).", [required.mode, required.min_days])
}

problems[msg] {
    required
    lock_enabled
    not retention
    msg := "Bucket requires WORM but Object Lock has no default retention, so new objects are not locked unless the upload sets a retention."
}

problems[msg] {
    required
    lock_enabled
    retention.Mode != required.mode
    msg := sprintf("Default retention mode is %v, expected %s.", [retention.Mode, required.mode])
}

problems[msg] {
    required
    lock_enabled
    retention
    not retention_days
    msg := "Default retention sets no period in Days or Years."
}

problems[msg] {
    required
    lock_enabled
    retention_days < required.min_days
    msg := sprintf("Default retention period is %s, shorter than the required %v days.", [period_label, required.min_days])
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    count(problems) > 0
}

# --- Metadata ---
currentConfiguration := concat(" ", sort(problems)) {
    result == "fail"
} else := sprintf("Bucket has Object Lock with a %s default retention of %s.", [retention.Mode, period_label]) {
    required
    lock_enabled
} else := "Bucket is not listed as requiring WORM."

expectedConfiguration := sprintf("Object Lock enabled with a default retention in %s mode of at least %v days (a year counts 365 days).", [required.mode, required.min_days]) {
    required
} else := "Buckets listed in worm_buckets must have Object Lock enabled with their default retention mode and at least their minimum period."
