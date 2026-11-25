# Remediation

The bucket in the finding is in the shared global namespace without approval, so once it is deleted another account can create a bucket with its name. The namespace is fixed at creation, so move the data to a new bucket in your account regional namespace:

1. Create the bucket and give it the old bucket's policy and settings. A copy takes the new bucket's default encryption, so export the old bucket's configuration to encryption.json and apply it unchanged, with its algorithm, KMS key and Bucket Key setting. Once both commands succeed, copy the data while clients still run. Leave out `--create-bucket-configuration` in us-east-1.

   ```bash
   aws s3api create-bucket --bucket <prefix>-<account-id>-<region>-an --bucket-namespace account-regional --region <region> --create-bucket-configuration LocationConstraint=<region>
   aws s3api get-bucket-encryption --bucket <bucket-name> --query ServerSideEncryptionConfiguration --output json > encryption.json
   aws s3api put-bucket-encryption --bucket <prefix>-<account-id>-<region>-an --server-side-encryption-configuration file://encryption.json
   aws s3 sync s3://<bucket-name> s3://<prefix>-<account-id>-<region>-an
   ```

2. Stop every write to the old bucket: stop its writers, turn off replication rules that send objects to it, and add a bucket policy Deny on `s3:PutObject` and `s3:ReplicateObject` for every principal. Keep the Deny until the bucket is deleted, and wait for requests in progress to finish.

3. Review the final copy with a dry run: its `delete:` lines are objects removed from the old bucket since the first copy, which `--delete` also removes from the new one. Then run it until `sync` exits with 0 (1 means a copy failed, 2 that objects were skipped, such as S3 Glacier Flexible Retrieval or Deep Archive objects not yet restored). A second dry run must list nothing, both buckets must show the same `Total Objects` and `Total Size`, and `head-object` on a copy must show the original's `ServerSideEncryption` and `SSEKMSKeyId`.

   ```bash
   aws s3 sync s3://<bucket-name> s3://<prefix>-<account-id>-<region>-an --delete --dryrun
   aws s3 sync s3://<bucket-name> s3://<prefix>-<account-id>-<region>-an --delete
   aws s3 ls s3://<bucket-name> --recursive --summarize
   aws s3 ls s3://<prefix>-<account-id>-<region>-an --recursive --summarize
   aws s3api head-object --bucket <prefix>-<account-id>-<region>-an --key <object-key>
   ```

4. Move clients and the replication rules to the new bucket. Objects still pending replication when the Deny went in stay in their source buckets; copy them with S3 Batch Replication.

5. Once no client uses the old bucket, delete it. `sync` copied current versions only, so if older versions must be kept, keep the old bucket and its Deny until they are no longer needed. `--force` permanently deletes every object still in it, and a versioned bucket first needs its object versions removed, for example with the console's Empty action.

   ```bash
   aws s3 rb s3://<bucket-name> --force
   ```

If the bucket is approved to stay in the global namespace until it is replaced, add its name to `authorized_global_buckets` instead. Buckets in Middle East (Bahrain) and Middle East (UAE), which have no account regional namespace, are not checked. Replace `<bucket-name>` with the bucket in the finding, `<account-id>` and `<region>` with its account and Region, `<prefix>` with a name of your choice, and `<object-key>` with a copied object.

## References

- [aws s3api create-bucket](https://docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html)
- [aws s3api get-bucket-encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-encryption.html)
- [aws s3api put-bucket-encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-encryption.html)
- [aws s3 sync](https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html)
- [aws s3 ls](https://docs.aws.amazon.com/cli/latest/reference/s3/ls.html)
- [aws s3api head-object](https://docs.aws.amazon.com/cli/latest/reference/s3api/head-object.html)
- [aws s3 rb](https://docs.aws.amazon.com/cli/latest/reference/s3/rb.html)
- [Namespaces for general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html)
- [General purpose bucket naming rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html)
- [Setting up permissions for live replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html)
- [Replicating existing objects with Batch Replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-batch-replication-batch.html)

Checked 2026-11-18 with AWS CLI 2.41.0: command syntax, flags and links.

## Testing Compliance
Deploy a general purpose bucket without account regional namespace; it should be detected.
