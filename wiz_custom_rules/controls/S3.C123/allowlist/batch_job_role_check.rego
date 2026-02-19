package wiz

# --- Logic ---
default result := "pass"

# Helper: Check input
has_input {
    input != null
}

# Helper: Get Authorized Roles from Parameters
# Expects a list of Role ARNs
authorized_roles := input.parameters.authorized_job_roles

# Helper: Get Job Definition Container Properties (Safe Access)
# The Job Role is defined inside containerProperties -> jobRoleArn
container_props := props {
    input.containerProperties != null
    props := input.containerProperties
} else := props {
    # Fallback for Wiz normalized structure
    input.properties.containerProperties != null
    props := input.properties.containerProperties
}

# Helper: Check if the Job Role is authorized
is_role_authorized(role_arn) {
    # Iterate over authorized list
    authorized_roles[_] == role_arn
}

# Helper: Find Unauthorized Role Usage
# We fail if a jobRoleArn is present AND it is not in our authorized list.
# Note: If jobRoleArn is missing/null, the job runs with NO permissions (EC2 instance profile might apply, but strict job role is absent).
# Depending on requirements, 'missing role' could be a Fail or Pass.
# Usually, for "Verify only authorized role", a missing role is technically compliant (it's not an unauthorized one).
has_unauthorized_role {
    role_arn := container_props.jobRoleArn
    role_arn != null
    not is_role_authorized(role_arn)
}

# --- Result Flow ---

result := "skip" {
    not has_input
} else := "fail" {
    # Fail if we can't find container properties (Invalid Job Definition)
    not container_props
} else := "fail" {
    # Fail if the configured role is not authorized
    has_unauthorized_role
}

# --- Metadata ---
currentConfiguration := sprintf("Batch Job is configured with an unauthorized IAM Role: %v", [container_props.jobRoleArn]) {
    result == "fail"
} else := "Batch Job is configured with an authorized IAM Role (or no role)."

expectedConfiguration := "Batch Job Definition 'containerProperties.jobRoleArn' must match one of the ARNs in 'authorized_job_roles'."