package wiz

# --- Configuration ---
authorized_principals := {
    "arn:aws:iam::123456789012:role/authorized-role",
    "arn:aws:iam::123456789012:root",
}

# Canonical user IDs that Allow statements may grant access to, written as
# the policy writes them. Empty means no canonical user may be granted
# access; add an ID once approved. IDs compare in lower case.
authorized_canonical_users := set()

# --- Logic ---
default result := "pass"

policy_doc := doc {
    is_string(input.bucketPolicy)
    doc := json.unmarshal(input.bucketPolicy)
} else := doc {
    is_object(input.bucketPolicy)
    doc := input.bucketPolicy
}

fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketPolicy.result == "Success"
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

# Service principals are out of scope for this control.
granted_principals[principal] {
    statement := statements[_]
    statement.Effect == "Allow"
    is_string(statement.Principal.AWS)
    principal := statement.Principal.AWS
}

granted_principals[principal] {
    statement := statements[_]
    statement.Effect == "Allow"
    principal := statement.Principal.AWS[_]
}

granted_principals["*"] {
    statement := statements[_]
    statement.Effect == "Allow"
    statement.Principal == "*"
}

unauthorized_principals := granted_principals - authorized_principals

# A canonical user ID names an account and is checked like any grantee.
canonical_values(v) := [v] { is_string(v) }
canonical_values(v) := v { is_array(v) }

granted_canonical_users[id] {
    statement := statements[_]
    statement.Effect == "Allow"
    id := canonical_values(statement.Principal.CanonicalUser)[_]
}

authorized_canonical_lower := {lower(trim_space(id)) | id := authorized_canonical_users[_]}

unauthorized_canonical_users := {sprintf("CanonicalUser:%s", [id]) |
    id := granted_canonical_users[_]
    count({lower(trim_space(id))} & authorized_canonical_lower) == 0
}

unauthorized_grants := unauthorized_principals | unauthorized_canonical_users

# An Allow with NotPrincipal grants everyone it does not list, so it fails.
not_principal_allow {
    statement := statements[_]
    statement.Effect == "Allow"
    object.get(statement, "NotPrincipal", null) != null
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    count(unauthorized_grants) > 0
} else := "fail" {
    not_principal_allow
}

# --- Metadata ---
grant_issues := array.concat(
    [msg | count(unauthorized_grants) > 0; msg := sprintf("Bucket policy grants access to unauthorized principal(s): %v", [unauthorized_grants])],
    [msg | not_principal_allow; msg := "Bucket policy has an Allow statement written with NotPrincipal, which grants every principal except those it lists and cannot be shown to stay within the authorized principals"],
)

currentConfiguration := concat("; ", grant_issues) {
    result == "fail"
} else := "Bucket policy grants access only to authorized principals, or grants no IAM principal access."

expectedConfiguration := sprintf("Allow statements in the bucket policy must only grant access to authorized IAM principals: %v, and authorized canonical users: %v, each named in Principal; an Allow written with NotPrincipal is reported", [authorized_principals, authorized_canonical_users])
