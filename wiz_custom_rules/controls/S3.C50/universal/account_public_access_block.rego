package wiz
# Note: This rule targets the AWS::S3::AccountPublicAccessBlock resource, distinct from individual buckets.
# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Check if configuration exists
# The input structure depends on the specific connector but generally maps to the BPA properties.
# We check for the standard structure found in Wiz/AWS Config.
has_bpa_config {
    input.properties != null
    # Sometimes it's directly under properties, sometimes nested.
    # We check for the 4 specific boolean flags.
}

# Helper: Get the config object (handles variations in input structure)
# Variant 1: Properties are at the root or direct properties
bpa_config := input.properties

# Helper: Verify all 4 flags are set to true
is_bpa_enabled {
    bpa_config.blockPublicAcls == true
    bpa_config.ignorePublicAcls == true
    bpa_config.blockPublicPolicy == true
    bpa_config.restrictPublicBuckets == true
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if properties are missing entirely
    not has_bpa_config
} else := "fail" {
    # Fail if any of the 4 flags is false or missing
    not is_bpa_enabled
}

# --- Metadata ---
currentConfiguration := "Account-level S3 Block Public Access is not fully enabled." {
    result == "fail"
} else := "Account-level S3 Block Public Access is fully enabled."

expectedConfiguration := "Account-level S3 Public Access Block must have BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets all set to true."