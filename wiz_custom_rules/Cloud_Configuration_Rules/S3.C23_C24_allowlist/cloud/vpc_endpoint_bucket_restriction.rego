package wiz

# --- Configuration ---
# S3 bucket ARNs the endpoint may grant access to.
authorized_buckets := {
    "arn:aws:s3:::authorized-bucket",
}

# --- Logic ---
default result := "pass"

is_s3_endpoint {
    endswith(input.ServiceName, ".s3")
}

policy_doc := doc {
    is_string(input.PolicyDocument)
    doc := json.unmarshal(input.PolicyDocument)
} else := doc {
    is_object(input.PolicyDocument)
    doc := input.PolicyDocument
}

statements[s] {
    is_array(policy_doc.Statement)
    s := policy_doc.Statement[_]
}

statements[s] {
    is_object(policy_doc.Statement)
    s := policy_doc.Statement
}

as_array(v) := v { is_array(v) } else := [v]

allow_statements[s] {
    s := statements[_]
    s.Effect == "Allow"
}

# An Allow may name an authorized bucket, or objects in one. The bucket name
# must be written out in full: a wildcard there can reach other buckets.
resource_authorized(res) {
    bucket := tocm_s3_arn_bucket(res)
    not regex.match(`[*?]`, bucket)
    p := tocm_arn_parts(res)
    tocm_arn_allowed(sprintf("arn:%s:s3:::%s", [p.partition, bucket]), authorized_buckets)
}

unauthorized_resources[res] {
    res := as_array(allow_statements[_].Resource)[_]
    not resource_authorized(res)
}

# An Allow written with NotResource grants every bucket except the listed ones.
allows_by_exclusion {
    object.get(allow_statements[_], "NotResource", null) != null
}

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    count(unauthorized_resources) > 0
} else := "fail" {
    allows_by_exclusion
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so it can access any bucket." {
    result == "fail"
    input.PolicyDocument == null
} else := sprintf("VPC endpoint allows access to unauthorized resource(s): %v", [unauthorized_resources]) {
    result == "fail"
    count(unauthorized_resources) > 0
} else := "VPC endpoint policy has an Allow written with NotResource, which grants every bucket it does not list." {
    result == "fail"
} else := "VPC endpoint restricts access to authorized buckets."

expectedConfiguration := sprintf("S3 VPC endpoint Allow statements must name only authorized buckets and their objects in Resource, and must not use NotResource: %v", [authorized_buckets])

# --- Matching helpers ---
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
