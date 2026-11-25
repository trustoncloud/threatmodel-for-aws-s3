# Remediation

An inventory configuration on the bucket in the finding sends reports to a bucket that is not authorized. Turning it off does not clear the finding, so delete the configuration or point it at an authorized bucket:

```bash
aws s3api list-bucket-inventory-configurations --bucket <bucket-name>
aws s3api delete-bucket-inventory-configuration --bucket <bucket-name> --id <inventory-id>
```

To keep the report, write it again with an authorized destination; `put-bucket-inventory-configuration` replaces the configuration with that ID, so copy its other settings from the list output. The destination bucket's policy must let S3 write the report.

```bash
aws s3api put-bucket-inventory-configuration --bucket <bucket-name> --id <inventory-id> --inventory-configuration '{"Id": "<inventory-id>", "IsEnabled": true, "IncludedObjectVersions": "Current", "Schedule": {"Frequency": "Weekly"}, "Destination": {"S3BucketDestination": {"Bucket": "<destination-bucket-arn>", "Format": "CSV"}}}'
```

If the destination is approved, add its ARN to `authorized_inventory_destinations` instead. Replace `<bucket-name>` with the bucket in the finding, `<inventory-id>` with the ID of the configuration whose destination the finding names, and `<destination-bucket-arn>` with an authorized bucket ARN.

## References

- [aws s3api list-bucket-inventory-configurations](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-bucket-inventory-configurations.html)
- [aws s3api delete-bucket-inventory-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-bucket-inventory-configuration.html)
- [aws s3api put-bucket-inventory-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-inventory-configuration.html)
- [Configuring Amazon S3 Inventory](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configure-inventory.html)
- [Cataloging and analyzing your data with S3 Inventory](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Create an unauthorized bucket to receive inventory; it should be detected.
