package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher. Destinations are matched as literal ARNs.
authorized_inventory_destinations := {
    "arn:aws:s3:::authorized-inventory-bucket",
}

# --- Logic ---
WizPolicy[result] {
    document := input.document[i]
    inv := document.resource.aws_s3_bucket_inventory[name]
    dest := terraLib.getValueArrayOrObject(inv.destination)
    b := terraLib.getValueArrayOrObject(dest.bucket)
    not authorized_inventory_destinations[b.bucket_arn]

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket_inventory",
        "resourceName": terraLib.get_resource_name(inv, name),
        "searchKey": sprintf("aws_s3_bucket_inventory[%s].destination.bucket.bucket_arn", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("destination bucket_arn must be in the authorized set: %v", [authorized_inventory_destinations]),
        "keyActualValue": sprintf("destination bucket_arn is '%v' (not authorized)", [b.bucket_arn]),
        "resourceTags": terraLib.get_resource_tags(inv),
    }
}
