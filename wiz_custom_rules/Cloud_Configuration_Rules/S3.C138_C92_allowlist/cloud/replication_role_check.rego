package wiz

# --- Configuration ---
authorized_replication_roles := {
    "arn:aws:iam::123456789012:role/authorized-replication-role",
}

# --- Logic ---
default result := "pass"

replication_role := input.bucketReplication.ReplicationConfiguration.Role

fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketReplication.result == "Success"
}

role_authorized {
    authorized_replication_roles[replication_role]
}

result := "skip" {
    not fetch_ok
} else := "skip" {
    input.bucketReplication == null
} else := "fail" {
    not role_authorized
}

# --- Metadata ---
currentConfiguration := sprintf("Replication uses unauthorized IAM role '%v'.", [replication_role]) {
    result == "fail"
} else := "Replication uses an authorized IAM role, or replication is not configured."

expectedConfiguration := sprintf("The replication configuration role must be in the authorized set: %v", [authorized_replication_roles])
