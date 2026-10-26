package wiz

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

covers_put_object_acl(action) { action == "s3:PutObjectAcl" }
covers_put_object_acl(action) { action == "s3:*" }
covers_put_object_acl(action) { action == "*" }
covers_put_object_acl(action) { action[_] == "s3:PutObjectAcl" }
covers_put_object_acl(action) { action[_] == "s3:*" }
covers_put_object_acl(action) { action[_] == "*" }

is_public_scalar(v) { v == "public-read" }
is_public_scalar(v) { v == "public-read-write" }

is_public_value(v) { is_public_scalar(v) }
is_public_value(v) { is_public_scalar(v[_]) }

targets_public_acl(statement) {
    conditions := statement.Condition[operator]
    val := conditions[key]
    lower(key) == "s3:x-amz-acl"
    is_public_value(val)
}

# A Deny on PutObjectAcl carrying a public canned-ACL value blocks the change.
has_public_acl_block {
    statement := statements[_]
    statement.Effect == "Deny"
    covers_put_object_acl(statement.Action)
    targets_public_acl(statement)
}

result := "skip" {
    not is_s3_endpoint
} else := "fail" {
    input.PolicyDocument == null
} else := "fail" {
    not has_public_acl_block
}

# --- Metadata ---
currentConfiguration := "VPC endpoint has no policy, so it does not block setting object ACLs to public." {
    result == "fail"
    input.PolicyDocument == null
} else := "VPC endpoint policy does not block setting object ACLs to public." {
    result == "fail"
} else := "VPC endpoint policy blocks setting object ACLs to public."

expectedConfiguration := "S3 VPC endpoint policy must Deny s3:PutObjectAcl when s3:x-amz-acl is public-read or public-read-write."
