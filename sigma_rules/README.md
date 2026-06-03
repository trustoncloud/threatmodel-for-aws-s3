## Intro

Sigma is a portable detection rule format for log and SIEM use, similar in spirit to how YARA describes patterns for files. It lets security teams write one rule in a simple, readable format and then convert or translate it into queries for different SIEMs and log platforms.

It’s especially useful for sharing detections across teams and tools without rewriting the logic every time. In practice, Sigma helps analysts express “what to look for” in logs, while the SIEM-specific backend handles how to query that data.

To learn more about Sigma, check their official documentation: https://sigmahq.io

As Sigma is focused on detection rules for logs, the scope are the Detective/Detect controls, as these controls monitor for a specific indicator of compromise (e.g., a logging event with specific parameters).

In this directory you can find the sigma rules and variables for the rules. Variables in Sigma are named placeholders embedded directly in a rule's detection logic, written as `%variable_name%` and resolved at query-generation time through a transformation file. It allows you to write a single rule and during query generation, you can fill up these placeholders with environment-specific values, that match your needs without rewriting the rule logic itself.

## Rule modes

The Sigma rules uses the same approach to the Open-source WIZ-CCR we published. Each control can be translated to up to 3 rule modes, depending on how the detection logic is defined or tuned.

**Universal mode:** where the log pattern provide all information need without any customer-supplied input. It is used when a rule should apply with no exceptions.

**Allowlist mode:** need customer input via variables. The detection works for all the events that are not related to a resource that customer marked as authorized, which can be an S3 bucket, an account ID, KMS key or anything else mentioned in our controls. Customer fill up the variable file with their custom values for authorized resources, and during conversion, the query generated check for events related only to resources not listed as authorized.

**Denylist mode:** opposite behavior from the allowlist. It needs customer input via variables, but in this mode the customer provide unauthorized resources as values, setting the scope to specific bad values. Useful when only a small portion of resources are considered a violation, and anything else is acceptable.

Important to note that not every control needs all 3 modes, and in fact very few implement all 3 modes. Some detections are unambiguous enough that only the universal variant makes sense, while others are context-dependent and only the allowlist or denylist variant is practical.

## Rule levels

The [Sigma documentation](https://sigmahq.io/docs/basics/rules.html#metadata-level) defines five level values: critical, high, medium, low and informational.

TrustOnCloud threatmodels use a five-step scale that almost matches Sigma. As of now we are usign the following mapping between TrustOnCloud control and Sigma rules:

|TrustOnCloud |	Sigma level |
|---|---|
|Very High	| critical |
|High	| high |
|Medium	| medium |
|Low	| low |
|Very Low |	informational |

## Variables

This folder holds the **per-customer settings** the Sigma rules read at conversion time — *"these are the bucket names my org has approved"*, *"these AWS accounts are allowed to share data with us"*. The rules stay generic and reusable; while your environment-specific values live here.

Each variable name carries the **control ID it belongs to** as a suffix, so it's obvious which rule a value affects.

| File | What it contains |
|---|---|
| `customer.aws.s3.example.yml` | Sample AWS S3 profile — placeholder buckets, account IDs, KMS keys |

### How to use the variables

1 - Edit or copy the variable files, replacing each placeholder with your real bucket names, account IDs, KMS keys, etc. Inline comments explain what each variable controls and which rule uses it.

2 - Run a sigma parser (e.g., [sigma-cli](https://github.com/SigmaHQ/sigma-cli), [RSigma](https://github.com/timescale/rsigma), [PySigma](https://github.com/SigmaHQ/pySigma)) with your variable file

3 - The generated SIEM queries contain your real values, to be used with your playbooks, SIEM, SOC, etc.

## Summary of AWS S3 controls and Sigma rules

| **#** | **Control** | **Control Definition** | **Control Testing** | **Sigma Rule Summary** | **Rule Level** | **Allowlist Mode** | **Denylist Mode** | **Universal Mode** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | C4 | Monitor and investigate all requests made with HTTP (e.g., via CloudTrail S3 data events with the lack of additionalEventData.CipherSuite). | Make an unencrypted AWS API call from one of your VPCs with VPC endpoint; it should be detected. | Detects S3 events that appear to be sent without TLS. | Low | N/A | N/A | Yes |
| 2 | C13 | Monitor that only authorized external buckets are used (e.g., via CloudTrail S3 data events in resources[].accountId and resources[].ARN). Both account ID and bucket name must be verified. | Make a call to an unauthorized bucket; it should be detected. | Detects S3 data events to external buckets that are not in approved account and bucket allowlists. | Medium | Yes | N/A | N/A |
| 3 | C33 | Monitor that only authorized AWS accounts provide KMS keys for each AWS account (using CloudTrail S3 data events in "response.x-amz-server-side-encryption-aws-kms-key-id"). | Encrypt an object using an unauthorized key; it should be detected. | Detects S3 data events using an unauthorized KMS key ARN or an unapproved AWS account. | Low | Yes | N/A | N/A |
| 4 | C35 | Monitor ObjectACL changes (or tentative changes) to public using CloudTrail S3 data events. | Make a call to create a public ObjectACL; it should be detected. | Detects object ACL changes that could make objects publicly accessible to AllUsers. | Low | N/A | Yes | Yes |
| 5 | C37 | Monitor and investigate anonymous requests to objects (e.g., using CloudTrail S3 data events with userIdentity.accountId=ANONYMOUS_PRINCIPAL). | Make an anonymous call; it should be detected. | Detects anonymous object requests in S3 data events. | Low | N/A | N/A | Yes |
| 6 | C43 | Monitor that all S3 connections are made with the virtual-hosted model (e.g., via CloudTrail S3 requestParameters.Host). | Make a path-style request to S3; it should be detected. | Detects S3 data events using path-style URL format instead of the required virtual-hosted-style. | Informational | Yes | N/A | Yes |
| 7 | C56 | Monitor changes to bucket ACLs to ensure they stay private (e.g., using the CloudTrail event PutBucketAcl and its field requestParameters.x-amz-acl, which should either be "private" or not exist). | Make a call to have a bucket ACL other than private; it should be detected. | Detects PutBucketAcl operations where ACL is not private. | Low | N/A | Yes | Yes |
| 8 | C68 | Monitor that only authorized KMS keys are used for each bucket (using CloudTrail S3 data events in "requestParameters.bucketName" and "response.x-amz-server-side-encryption-aws-kms-key-id"). | Make a request encrypted with an unauthorized KMS key; it should be detected. | Detects S3 encryption events where the bucket-to-KMS-key pairing does not match an approved combination. Pair integrity is preserved (bucket A is only allowed with key A, never key B) by generating one selection block per approved pair from the customer's `authorized_bucket_kms_pairs` list-of-objects. | Low | Yes | N/A | N/A |
| 9 | C82 | Monitor and investigate any requests not using SigV4 (e.g., via CloudTrail S3 when the additionalEventData.SignatureVersion is different from "SigV4"). | Make a non-SigV4 AWS API call; it should be detected. | Detects S3 requests using signature versions other than SigV4 or explicitly denylisted signature types. | Informational | N/A | Yes | Yes |
| 10 | C85 | Monitor and investigate all requests that do not use the HTTP authorization header (e.g., via CloudTrail S3 events where the additionalEventData.AuthenticationMethod is different from "AuthHeader"). | Make 1) a presigned AWS API call and 2) a POST request without the HTTP authorization header; it should be detected. | Request Without Authorization Header. Detects S3 requests where AuthenticationMethod is not AuthHeader. | Low | N/A | Yes | Yes |
| 11 | C115 | For all external buckets with bucket-owner-full-control ACL requirements but without S3 Object Ownership handover, monitor that the PutObject operation does not include the ACL header. | Make a request to an external bucket with a bucket-owner-full-control ACL requirement but without an S3 Object Ownership handover requirement; it should be detected. | PutObject With ACL Header To External Bucket. Detects PutObject requests to external buckets that include an ACL header where it should be absent. | Medium | Yes | N/A | Yes |
| 12 | C148 | For buckets (or paths) requiring SSE-C, monitor that only authorized encryption is used on each bucket or path (using CloudTrail S3 data events in requestParameters.bucketName and response.x-amz-server-side-encryption-customer-algorithm). | Make a request to a bucket (or path) requiring SSE-C without the proper encryption; it should be detected. |  For buckets (or paths) requiring SSE-C, monitor that only authorized encryption is used on each bucket or path (using CloudTrail S3 data events in requestParameters.bucketName and response.x-amz-server-side-encryption-customer-algorithm). | Low | Yes | N/A | N/A |
| 13 | C157 | Monitor PutBucketLogging to detect bucket server access logging changes, including deactivation and bucket changes (i.e., using the CloudTrail event "PutBucketLogging" and the "requestParameters.BucketLoggingStatus" field to examine the lack of the "LoggingEnabled" key or an unauthorized bucket in "requestParameters.BucketLoggingStatus.LoggingEnabled.TargetBucket"). | Make a call to 1) disable bucket logging, or 2) change to an unauthorized bucket; it should be detected. | Monitor PutBucketLogging to detect bucket server access logging changes, including deactivation and bucket changes | Informational | Yes | N/A | N/A |
| 14 | C160 | Monitor CreateAccessPoint to detect unauthorized buckets or AWS accounts (i.e., using CloudTrail event CreateAccessPoint and its fields "requestParameters.CreateAccessPointRequest.Bucket" and "requestParameters.CreateAccessPointRequest.BucketAccountId"). | Call the API to create a cross-account access point with an unauthorized 1) bucket or 2) an authorized bucket in an unauthorized AWS account; it should be detected. | Detects CreateAccessPoint and CreateMultiRegionAccessPoint operations where the target bucket or the bucket's owning account is not in the authorized allowlists.| Medium | Yes | N/A | N/A |
| 15 | C163 | Monitor requests not using DSSE-KMS when required (e.g., using CloudTrail log event name(s), CloudTrail S3 data events with field(s) requestParameter.bucketName, and "response.x-amz-server-side-encryption-aws"). | Make a request not using DSSE-KMS on a required S3 bucket; it should be detected. | Detects write operations to DSSE-KMS-required buckets where DSSE-KMS encryption was not applied to the object. | Informational | Yes | N/A | N/A |

