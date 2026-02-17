package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Get Inventory Configurations (Safe Access)
# Returns the list of configured reports, or empty list if null
inventory_configs := configs {
    input.properties.inventoryConfigurations != null
    configs := input.properties.inventoryConfigurations
} else := []

# Helper: Get Authorized Destinations from Parameters
# Expects a list of ARNs, e.g., ["arn:aws:s3:::my-central-log-bucket"]
authorized_destinations := input.parameters.authorized_inventory_destinations

# Helper: Check if a destination is authorized
is_authorized(dest_arn) {
    # Check exact match
    # Implicitly iterates over the authorized list
    authorized_destinations[_] == dest_arn
}

# Helper: Check for Unauthorized Destinations
has_unauthorized_destination {
    # Iterate over all inventory configurations
    config := inventory_configs[_]
    
    # Extract the destination bucket ARN
    current_dest := config.Destination.S3BucketDestination.Bucket
    
    # Check if this destination is NOT in our allowlist
    not is_authorized(current_dest)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "pass" {
    # If no inventory configs exist, there is no risk of data leak via this vector
    count(inventory_configs) == 0
} else := "fail" {
    # Fail if any configured destination is not in the allowlist
    has_unauthorized_destination
}

# --- Metadata ---
currentConfiguration := "Bucket sends Inventory reports to an unauthorized destination." {
    result == "fail"
} else := "Bucket sends Inventory reports only to authorized destinations (or inventory is disabled)."

expectedConfiguration := "S3 Inventory configurations must target destination buckets listed in 'authorized_inventory_destinations'."