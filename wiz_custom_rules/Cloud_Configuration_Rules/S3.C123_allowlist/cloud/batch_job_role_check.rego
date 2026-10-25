package wiz

# --- Configuration ---
authorized_batch_job_roles := {
    "arn:aws:iam::123456789012:role/batch-operations-role",
}

# --- Logic ---
default result := "pass"

# The job descriptor sits under Job; the execution role is at Job.RoleArn.
has_job {
    input.Job.JobArn != null
}

has_job {
    input.Job.JobId != null
}

role_authorized {
    authorized_batch_job_roles[input.Job.RoleArn]
}

result := "skip" {
    not has_job
} else := "fail" {
    not role_authorized
}

# --- Metadata ---
currentConfiguration := sprintf("Batch job runs as role '%v'.", [input.Job.RoleArn]) {
    result == "fail"
    input.Job.RoleArn != null
} else := "Batch job has no execution role recorded." {
    result == "fail"
} else := "Batch job runs as an authorized role."

expectedConfiguration := sprintf("Batch job RoleArn must be one of the authorized roles: %v", [authorized_batch_job_roles])
