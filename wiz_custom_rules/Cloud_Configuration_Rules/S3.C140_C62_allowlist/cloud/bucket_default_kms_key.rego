package wiz

# --- Configuration ---
# Key ARNs any bucket may use for default encryption. Keep in sync with S3.C67.
authorized_kms_key_ids := {
    "arn:aws:kms:us-east-1:123456789012:key/authorized-key",
}

# Bucket name to the only key ARNs its default encryption may use. Other
# buckets use authorized_kms_key_ids. Names match exactly.
authorized_kms_key_ids_by_bucket := {
    "finance-data-bucket": {"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
}

# Buckets that may keep SSE-S3 because their writers cannot use KMS, such as
# a server access log destination. Names match exactly.
sse_s3_buckets := {
    "example-access-logs-bucket",
}

# --- Logic ---
default result := "pass"

# The payload shows the default for new objects only, never stored objects.
fetch_ok {
    input.WizMetadata.objectFetchStatus.bucketEncryptionConfiguration.result == "Success"
}

bucket_keys := keys {
    keys := authorized_kms_key_ids_by_bucket[input.Name]
} else := authorized_kms_key_ids

# With no rule setting a default, S3 encrypts new objects with SSE-S3.
defaults[d] {
    d := input.bucketEncryptionConfiguration.ServerSideEncryptionConfiguration.Rules[_].ApplyServerSideEncryptionByDefault
    is_object(d)
}

# SSE-KMS and DSSE-KMS encrypt with a KMS key; AES256 is SSE-S3.
kms_algorithms := {"aws:kms", "aws:kms:dsse"}

sse_s3_approved {
    sse_s3_buckets[input.Name]
}

sse_s3_allowed(d) {
    sse_s3_approved
    d.SSEAlgorithm == "AES256"
}

kms_default {
    kms_algorithms[defaults[_].SSEAlgorithm]
}

algorithm_label(a) := "SSE-S3 (AES256)" {
    a == "AES256"
} else := sprintf("%v", [a])

# KMSMasterKeyID is null when no key is named, and S3 then uses aws/s3.
kms_key(d) := k {
    is_string(d.KMSMasterKeyID)
    k := trim_space(d.KMSMasterKeyID)
    k != ""
}

# A bare alias resolves in the uploader's account, so it can name any key.
bare_alias(k) {
    startswith(k, "alias/")
}

# A bare key ID is read as the bucket owner's key in the bucket's Region.
key_id_pattern := `^(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`

bucket_partition := p {
    p := tocm_arn_parts(input.BucketArn).partition
} else := "aws"

bucket_region := r {
    r := input.BucketRegion
    is_string(r)
    r != ""
} else := r {
    r := input.WizMetadata.region
    is_string(r)
    r != ""
}

bucket_account := a {
    a := input.WizMetadata.accountId
    is_string(a)
    a != ""
}

key_arn(k) := k {
    tocm_arn_parts(k)
} else := sprintf("arn:%s:kms:%s:%s:key/%s", [bucket_partition, bucket_region, bucket_account, k]) {
    regex.match(key_id_pattern, k)
}

key_authorized(k) {
    tocm_arn_allowed(key_arn(k), bucket_keys)
}

problems[msg] {
    count(defaults) == 0
    not sse_s3_approved
    msg := "Bucket has no default encryption rule, so new objects are encrypted with SSE-S3 (the S3 default)."
}

problems[msg] {
    d := defaults[_]
    not kms_algorithms[d.SSEAlgorithm]
    not sse_s3_allowed(d)
    msg := sprintf("Bucket default encryption is %s, not a KMS key.", [algorithm_label(d.SSEAlgorithm)])
}

problems[msg] {
    d := defaults[_]
    kms_algorithms[d.SSEAlgorithm]
    not kms_key(d)
    msg := sprintf("Bucket default encryption is %s with no key named, so S3 uses the AWS managed key aws/s3.", [d.SSEAlgorithm])
}

problems[msg] {
    d := defaults[_]
    kms_algorithms[d.SSEAlgorithm]
    k := kms_key(d)
    bare_alias(k)
    msg := sprintf("Bucket default encryption names the key by alias '%s', which resolves in the uploader's account.", [k])
}

problems[msg] {
    d := defaults[_]
    kms_algorithms[d.SSEAlgorithm]
    k := kms_key(d)
    not bare_alias(k)
    not key_authorized(k)
    msg := sprintf("Bucket default encryption key '%s' is not authorized for this bucket.", [k])
}

result := "skip" {
    not fetch_ok
} else := "fail" {
    count(problems) > 0
}

# --- Metadata ---
currentConfiguration := concat(" ", sort(problems)) {
    result == "fail"
} else := "Bucket default encryption is SSE-S3, approved for this bucket." {
    sse_s3_approved
    not kms_default
} else := "Bucket default encryption uses a KMS key authorized for this bucket."

expectedConfiguration := sprintf("Bucket default encryption must be SSE-KMS (aws:kms or aws:kms:dsse) with a KMS key ARN authorized for this bucket: %v. Stored objects and uploads that name their own key are not shown by the bucket settings.", [sort(bucket_keys)]) {
    not sse_s3_approved
} else := sprintf("Bucket default encryption must be SSE-S3, approved for this bucket, or SSE-KMS (aws:kms or aws:kms:dsse) with a KMS key ARN authorized for it: %v.", [sort(bucket_keys)])

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
