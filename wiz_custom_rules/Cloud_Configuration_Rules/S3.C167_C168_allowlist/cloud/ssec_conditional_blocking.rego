package wiz

# --- Configuration ---
# Buckets that require SSE-C and therefore must NOT block it: a bucket name for
# the whole bucket, or "bucket/prefix/" for one path inside it. The block
# setting covers the whole bucket, so a path entry keeps SSE-C allowed on its
# bucket. Every other bucket must block SSE-C. Keep in sync with S3.C147.
buckets_requiring_ssec := {
    "ssec-required-bucket",
    "mixed-bucket/secure/",
}

# --- Logic ---
default result := "pass"

encryption_ok {
    input.WizMetadata.objectFetchStatus.bucketEncryptionConfiguration.result == "Success"
}

is_ssec_required {
    buckets_requiring_ssec[input.Name]
}

is_ssec_required {
    startswith(buckets_requiring_ssec[_], concat("", [input.Name, "/"]))
}

value_is(v, target) { v == target }
value_is(v, target) { v[_] == target }

# The bucket's default encryption setting blocks SSE-C uploads for the whole
# bucket (BlockedEncryptionTypes; the S3 default since April 2026).
setting_blocks_ssec {
    rule := input.bucketEncryptionConfiguration.ServerSideEncryptionConfiguration.Rules[_]
    value_is(rule.BlockedEncryptionTypes.EncryptionType, "SSE-C")
}

result := "skip" {
    not encryption_ok
} else := "fail" {
    is_ssec_required
    setting_blocks_ssec
} else := "fail" {
    not is_ssec_required
    not setting_blocks_ssec
}

# --- Metadata ---
currentConfiguration := "Bucket requires SSE-C but its default encryption setting blocks SSE-C uploads (BlockedEncryptionTypes SSE-C)." {
    result == "fail"
    is_ssec_required
} else := "Bucket does not require SSE-C but its default encryption setting does not block it." {
    result == "fail"
} else := "Bucket's default encryption setting handles SSE-C according to its requirement."

expectedConfiguration := "Buckets in the required set (including a bucket with a required path) must set BlockedEncryptionTypes to NONE. Every other bucket must set BlockedEncryptionTypes to SSE-C."
