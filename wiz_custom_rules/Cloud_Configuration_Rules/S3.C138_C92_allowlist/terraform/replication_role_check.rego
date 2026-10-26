package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_replication_roles := {
    "arn:aws:iam::123456789012:role/authorized-replication-role",
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    rc := document.resource.aws_s3_bucket_replication_configuration[name]
    terraLib.validKey(rc, "role")
    not authorized_replication_roles[rc.role]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_replication_configuration",
        "resourceName": terraLib.get_resource_name(rc, name),
        "searchKey": sprintf("aws_s3_bucket_replication_configuration[%s].role", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("role must be in the authorized set: %v", [authorized_replication_roles]),
        "keyActualValue": sprintf("role is '%v' (not authorized)", [rc.role]),
        "resourceTags": terraLib.get_resource_tags(rc),
    }
}
