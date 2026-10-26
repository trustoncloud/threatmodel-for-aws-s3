package wiz

# --- Configuration ---
authorized_inventory_destinations := {
    "arn:aws:s3:::authorized-inventory-bucket",
}

# --- Logic ---
default result := "pass"

# Accept both a bare list and the AWS API wrapper shape.
inventory_configs := configs {
    configs := input.inventoryConfigurations
    is_array(configs)
} else := configs {
    configs := input.inventoryConfigurations.InventoryConfigurationList
}

fetch_ok {
    input.WizMetadata.objectFetchStatus.inventoryConfigurations.result == "Success"
}

unauthorized_destinations[dest] {
    dest := inventory_configs[_].Destination.S3BucketDestination.Bucket
    not authorized_inventory_destinations[dest]
}

result := "skip" {
    not fetch_ok
} else := "skip" {
    input.inventoryConfigurations == null
} else := "fail" {
    count(unauthorized_destinations) > 0
}

# --- Metadata ---
currentConfiguration := sprintf("Inventory reports are sent to unauthorized destination(s): %v", [unauthorized_destinations]) {
    result == "fail"
} else := "Inventory destinations are authorized, or inventory is not configured."

expectedConfiguration := sprintf("Every inventory destination bucket must be in the authorized set: %v", [authorized_inventory_destinations])
