package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# The four account-level Block Public Access flags. Provider default is false
# for each, so a flag that is omitted or false is a violation.
required_flags := {
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
}

is_true(v) { v == true }
is_true(v) { v == "true" }

# --- Logic ---
# Universal: every declared aws_s3_account_public_access_block must enable all
# four flags. One finding per missing or false flag.
WizPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_s3_account_public_access_block[name]
    flag := required_flags[_]
    not is_true(object.get(resource, flag, false))

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_account_public_access_block",
        "resourceName": terraLib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_s3_account_public_access_block[%s].%s", [name, flag]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("%s must be true", [flag]),
        "keyActualValue": sprintf("%s is false or not set (provider default is false)", [flag]),
        "resourceTags": terraLib.get_resource_tags(resource),
    }
}
