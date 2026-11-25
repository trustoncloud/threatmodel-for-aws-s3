package wiz

# --- Configuration ---
# Authorized replication roles: source bucket name, then the IAM role ARNs it
# may use. A bucket that replicates with no entry fails. A role listed under
# many buckets is approved for each of them.
authorized_replication_roles := {
    "authorized-source-bucket": {
        "arn:aws:iam::123456789012:role/authorized-replication-role",
    },
}

# --- Logic ---
default result := "pass"

# --- toc-match begin: arn v1 ---
# Parts of an AWS ARN; the resource keeps any further ":" characters.
tocm_arn_parts(arn) := {"partition": s[1], "service": s[2], "region": s[3], "account": s[4], "resource": r} {
    is_string(arn)
    s := split(trim_space(arn), ":")
    count(s) >= 6
    s[0] == "arn"
    s[1] != ""
    s[2] != ""
    r := concat(":", array.slice(s, 5, count(s)))
    r != ""
}

tocm_arn_equal(a, b) {
    tocm_arn_parts(a) == tocm_arn_parts(b)
}

tocm_arn_allowed(arn, allowed) {
    tocm_arn_equal(arn, allowed[_])
}

# Bucket name of an S3 bucket or object ARN (arn:aws:s3:::bucket[/key]).
tocm_s3_arn_bucket(arn) := b {
    p := tocm_arn_parts(arn)
    p.service == "s3"
    p.region == ""
    p.account == ""
    b := split(p.resource, "/")[0]
    b != ""
}
# --- toc-match end: arn v1 ---

# bucketReplication is null when the bucket has no replication.
fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketReplication.result == "Success"
}

replication_role := input.bucketReplication.ReplicationConfiguration.Role

role_label := r {
    r := replication_role
    is_string(r)
    r != ""
} else := "none"

bucket_listed {
    authorized_replication_roles[input.Name]
}

role_authorized {
    tocm_arn_allowed(replication_role, authorized_replication_roles[input.Name])
}

listed_roles := sort([r | r := authorized_replication_roles[input.Name][_]])

result := "skip" {
    not fetch_ok
} else := "skip" {
    input.bucketReplication == null
} else := "fail" {
    not role_authorized
}

# --- Metadata ---
currentConfiguration := sprintf("Bucket '%s' replicates with IAM role '%s' but has no entry in authorized_replication_roles.", [input.Name, role_label]) {
    result == "fail"
    not bucket_listed
} else := sprintf("Bucket '%s' replicates with IAM role '%s', which is not authorized for this bucket.", [input.Name, role_label]) {
    result == "fail"
} else := "Replication uses an IAM role authorized for this bucket, or replication is not configured."

expectedConfiguration := sprintf("The replication role of bucket '%s' must be one of the IAM roles listed for it in authorized_replication_roles: %v", [input.Name, listed_roles]) {
    is_string(input.Name)
} else := "The replication role of each bucket must be one of the IAM roles listed for that bucket in authorized_replication_roles."
