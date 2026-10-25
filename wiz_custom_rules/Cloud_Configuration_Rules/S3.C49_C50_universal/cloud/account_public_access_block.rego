package wiz

# --- Logic ---
default result := "pass"

# Account-level Block Public Access, read from
# accountPublicAccessBlockConfiguration. Accept both the wrapped and flat
# rendering of the configuration object.
pab := cfg {
    cfg := input.accountPublicAccessBlockConfiguration.PublicAccessBlockConfiguration
} else := cfg {
    cfg := input.accountPublicAccessBlockConfiguration
}

# Only judge when Wiz successfully fetched the account-level configuration;
# null with a fetch error means unreadable, not absent.
fetch_ok {
    input.WizMetadata.objectFetchStatus.accountPublicAccessBlockConfiguration.result == "Success"
}

all_enabled {
    pab.BlockPublicAcls == true
    pab.IgnorePublicAcls == true
    pab.BlockPublicPolicy == true
    pab.RestrictPublicBuckets == true
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    input.accountPublicAccessBlockConfiguration == null
} else := "fail" {
    not all_enabled
}

# --- Metadata ---
currentConfiguration := "Account-level S3 Block Public Access is not configured for this account." {
    result == "fail"
    input.accountPublicAccessBlockConfiguration == null
} else := "Account-level S3 Block Public Access is not fully enabled." {
    result == "fail"
} else := "Account-level S3 Block Public Access is fully enabled."

expectedConfiguration := "Account-level S3 Block Public Access must have BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets all set to true."
