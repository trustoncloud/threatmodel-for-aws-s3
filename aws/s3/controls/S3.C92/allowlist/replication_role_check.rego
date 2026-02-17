package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Check if Replication is enabled
# Logic: We only check roles if replication is actually configured.
# If no replication exists, the resource is compliant (nothing to check).
has_replication {
    input.properties.replicationConfiguration != null
}

# Helper: Get the configured Role ARN
# AWS S3 Replication Config defines a single Role for the configuration
current_role := input.properties.replicationConfiguration.role

# Helper: Get Authorized Roles from parameters
# Expects a list of full ARN strings
authorized_roles := input.parameters.authorized_replication_roles

# Helper: Check if the current role is authorized
is_authorized_role {
    # Iterate over the authorized list to find a match
    authorized_roles[_] == current_role
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "pass" {
    # If replication is NOT enabled, we pass (implicit compliance)
    not has_replication
} else := "fail" {
    # Fail if replication is ON but the role is NOT in the authorized list
    not is_authorized_role
}

# --- Metadata ---
currentConfiguration := sprintf("Replication is enabled using unauthorized role: '%v'.", [current_role]) {
    result == "fail"
} else := "Replication is not enabled or uses an authorized role."

expectedConfiguration := "Replication Configuration must use an IAM Role ARN listed in 'authorized_replication_roles'."