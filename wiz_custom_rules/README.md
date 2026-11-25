# AWS S3 Customised CCRs for Wiz

27 Wiz custom configuration rules covering 25 AWS S3 assurance controls from
the TrustOnCloud AWS S3 ThreatModel. Each rule checks your live AWS estate
(Cloud matcher), your Terraform code before deployment (Terraform matcher),
or both. Every rule is test-validated, with property paths verified against
real Wiz payloads and the AWS provider documentation.

These rules are gap-fillers: each covers an assurance control that Wiz's
built-in CCR library does not address. Severities follow the ThreatModel
weighted priority.

---

## Rule naming: two control IDs per rule

Most rule folders carry two control IDs, for example `S3.C6_C7_universal`:

- The **first ID** is the paired Directive or Preventative control. The
  Terraform matcher implements it: it verifies your IaC declares the
  safeguard before deployment.
- The **second ID** is the Assurance control. The cloud matcher verifies it:
  it checks the safeguard is live on the deployed resource.

One rule therefore covers a pre-deploy and a post-deploy control as a single
enforcement intent. Each rule's description names both IDs, the mapping CSV
carries a "Paired Control" column, and the `controlId` / `pairedControlId`
tags let you filter in the Wiz console by either ID. Rules with only one
surface keep a single ID (S3.C123 is cloud-only: Batch jobs have no
Terraform resource). S3.C1_C2 and S3.C171_C172 are Terraform-only: SCPs have
no Wiz runtime scan surface, and Wiz does not collect a bucket's ABAC status.

---

## What is in this delivery

27 controls, delivered as 29 rule folders (S3.C19_C20 and S3.C174_C177 ship
two modes).

| Rule | Severity | What it flags |
|---|---|---|
| S3.C49_C50 | Critical | Account-level S3 Block Public Access not fully enabled |
| S3.C99_C100 | Critical | Bucket policies that do not restrict access to authorized VPCs |
| S3.C1_C2 | High | Organization SCPs missing the Deny on unencrypted S3 traffic or the Deny on TLS below 1.2 (Terraform-only) |
| S3.C6_C7 | High | Buckets whose policy does not deny unencrypted traffic and TLS below 1.2 |
| S3.C19_C20 | High | S3 VPC endpoints not restricted to authorized AWS Organizations or accounts |
| S3.C34_C36 | High | S3 VPC endpoints that do not block setting object ACLs to public |
| S3.C66_C67 | High | Buckets not enforcing the authorized KMS key(s) on uploads |
| S3.C74_C75 | High | Buckets requiring WORM without Object Lock or with a default retention other than authorized (mode, minimum period) |
| S3.C106_C110 | High | Bucket policies that do not restrict access to authorized access points |
| S3.C146_C147 | High | SSE-C-required buckets not enforcing customer-key encryption on uploads |
| S3.C150_C151 | High | Bucket policies granting access to unauthorized IAM principals |
| S3.C167_C168 | High | SSE-C allowed on buckets that must block it, or blocked where required |
| S3.C3_C5 | Medium | S3 VPC endpoints whose policy does not deny both unencrypted requests and TLS below 1.2 |
| S3.C23_C24 | Medium | S3 VPC endpoints granting access beyond authorized buckets |
| S3.C140_C62 | Medium | Buckets whose default encryption is not an authorized KMS key (SSE-S3, aws/s3, an alias or another key) |
| S3.C134_C87 | Medium | Replication enabled on buckets not authorized to replicate |
| S3.C134_C88 | Medium | Replication rules that differ from the bucket's authorized routes (target, replica KMS key, ownership, RTC) |
| S3.C138_C92 | Medium | Replication using unauthorized IAM roles |
| S3.C137_C102 | Medium | CloudFront associations with unauthorized distributions or identities |
| S3.C134_C117 | Medium | Replication rules without replication metrics enabled |
| S3.C123 | Medium | Batch Operations jobs running as an unauthorized IAM role (cloud-only) |
| S3.C159_C161 | Medium | Access points targeting unauthorized buckets or bucket-owner accounts |
| S3.C171_C172 | Medium | ABAC enabled on buckets not authorized for it, or off on authorized ones (Terraform-only) |
| S3.C174_C177 | Medium | Buckets in the global namespace instead of their account regional namespace |
| S3.C135_C95 | Low | Bucket notifications delivered to unauthorized receivers |
| S3.C155_C156 | Low | Bucket policies not blocking unauthorized service roles |
| S3.C136_C97 | Informational | Inventory exports to unauthorized destinations |

## Coverage breakdown

| Axis | Count |
|---|---|
| Controls | 27 |
| Rule folders (control x mode) | 29 |
| Cloud matchers | 25 (S3.C1_C2 and S3.C171_C172 are Terraform-only) |
| Terraform matchers | 26 (S3.C123 is cloud-only) |
| Cloud OPA tests passing | 629 of 629 |
| Terraform fixture checks passing | 56 of 56 |

Modes shipped per control:

| Modes | Rules |
|---|---|
| universal | S3.C1_C2, S3.C3_C5, S3.C6_C7, S3.C34_C36, S3.C49_C50, S3.C134_C117 |
| allowlist, universal | S3.C19_C20, S3.C174_C177 |
| allowlist | all others |

- **allowlist**: flag any resource whose value is not in your authorized set.
- **universal**: enforce the secure state on every resource (no exceptions).

| Wiz native type | Rules |
|---|---|
| `bucket` | 19 |
| `vpcEndpoint` | S3.C3_C5, S3.C19_C20, S3.C23_C24, S3.C34_C36 (scoped to S3 endpoints by service name) |
| `s3AccessPoint` | S3.C159_C161 |
| `s3#job` | S3.C123 |

| Terraform resource | Rules |
|---|---|
| `aws_s3_bucket`, `aws_s3_bucket_policy` | the bucket-policy family (C7, C67, C100, C102, C110, C147, C151, C156) |
| `aws_s3_bucket_replication_configuration`, `aws_s3_bucket` (inline `replication_configuration`) | C87, C88, C92, C117 |
| `aws_s3_bucket_notification` / `aws_s3_bucket_inventory` | C95 / C97 |
| `aws_s3_account_public_access_block` | C50 |
| `aws_s3_bucket_server_side_encryption_configuration` | C62, C168 |
| `aws_s3_bucket` (inline `server_side_encryption_configuration`), `aws_s3_object`, `aws_s3_object_copy`, `aws_s3_bucket_object` | C62 |
| `aws_s3_bucket_object_lock_configuration`, `aws_s3_bucket` (`object_lock_enabled`, inline `object_lock_configuration`) | C75 |
| `aws_vpc_endpoint`, `aws_vpc_endpoint_policy` | C5, C20, C24, C36 |
| `aws_s3_access_point` | C161 |
| `aws_s3_bucket` (`bucket_namespace`) | C177 |
| `aws_s3_bucket_abac`, `aws_s3_bucket` | C172 |
| `aws_organizations_policy`, `aws_organizations_policy_attachment`, `aws_organizations_organization` | C2 |

All policy-reading Terraform matchers handle policies written as JSON strings
(heredoc or `jsonencode`) and as `aws_iam_policy_document` data sources.

---

## Package layout

```
aws-s3/
├── Cloud_Configuration_Rules/          The deployable rules (27 folders)
│   └── S3.<parent>_<assurance>_<mode>/
│       ├── cloud/<rule>.rego           Cloud matcher (runtime)
│       ├── terraform/<rule>.rego       Terraform matcher (IaC)
│       ├── terraform/remediation.md    How to fix the Terraform finding
│       └── metadata/
│           ├── metadata.json           Name, severity, native types, tags
│           ├── description.md
│           └── remediation.md          How to fix the live resource
├── terraform_test_samples/             Sample .tf for self-validation,
│   └── S3.<parent>_<assurance>/        keyed to match the rule folders
│       └── test_<mode>_{pass,fail}.tf
├── main.tf                             Wiz Terraform module (reads Cloud_Configuration_Rules/)
├── providers.tf                        Wiz provider + auth instructions
├── versions.tf
├── pack.json                           Manifest for the ThreatModel Assurance module
├── AWS S3 Controls and Wiz Mapping.csv Control-to-rule mapping incl. paired controls
└── README.md                           This document
```

---

## Versioning

Versions are repo-wide rather than per service, and follow a semver-lite scheme:

- A minor bump, `v0.X.0`, means a new service.
- A patch bump, `v0.X.Y`, means a change to a service already published: new
  rules, wider coverage, or fixes to rules already shipped.

Because the version covers the whole repository, a release names the one service
it updates and leaves every other package unchanged. A package downloaded from a
GitHub release carries its service and version in its filename.

---

## Deploying to Wiz

### 1. Create a Wiz service account

In Wiz: Settings -> Access Management -> Service Accounts. Use type
"Custom Integration (GraphQL API)". Tick all permission boxes under the
"Cloud Configuration Rule" and "Cloud Configuration" sections.

### 2. Set credentials

```bash
export WIZ_URL="https://api.<host>.app.wiz.io/graphql"   # Tenant Info -> API Endpoint URL
export WIZ_CLIENT_ID=<your_wiz_client_id>
export WIZ_CLIENT_SECRET=<your_wiz_client_secret>
```

### 3. Apply

```bash
terraform init
terraform plan      # review what will be created
terraform apply
```

`terraform destroy` removes the rules cleanly if you want to back them out.

---

## Before you apply

### Enablement posture

- **Universal-mode rules ship enabled.** They enforce a fixed secure state,
  carry no placeholders, and produce real findings on the first scan.
- **Allowlist rules ship disabled.** They depend on your environment-specific
  values and stay dormant until you set those values and enable them. This
  avoids a first-scan flood of placeholder-driven findings.

To enable an allowlist rule after configuring it, toggle it in the Wiz UI, or
set `"enabled": true` in that rule's `metadata/metadata.json` and re-run
`terraform apply`.

### Replace placeholder allowlist values

Allowlist rules carry placeholder values under a `--- Configuration ---`
comment block at the top of each `.rego` file. Set your organization's values
in BOTH the cloud and terraform matcher of the same rule, and keep them in
sync.

| Rule | Set this |
|---|---|
| S3.C19_C20 | Authorized AWS Organization IDs, org paths, or account IDs |
| S3.C23_C24 | Bucket ARNs the S3 VPC endpoints may access |
| S3.C66_C67 and S3.C140_C62 | Authorized KMS key ARNs (`authorized_kms_key_ids`, one shared list, set in both rules) |
| S3.C140_C62 | Keys of a bucket's own, as a map from bucket name to key ARNs, and the buckets approved to keep SSE-S3 (such as server access log destinations) |
| S3.C74_C75 | Buckets requiring WORM, each with its default Object Lock mode and minimum retention in days |
| S3.C134_C87 and S3.C134_C88 | Authorized replication routes: each source bucket, the destination bucket ARNs it may replicate to, and each route's replica KMS key, owner override and RTC (one shared list, set in both rules) |
| S3.C138_C92 | Authorized replication role ARNs for each source bucket: a map from bucket name to the role ARNs its replication may use |
| S3.C135_C95 | Authorized notification receivers (SNS, SQS, Lambda ARNs), and the buckets allowed to send events to EventBridge |
| S3.C136_C97 | Authorized inventory destination bucket ARNs |
| S3.C99_C100 | Authorized VPC IDs |
| S3.C137_C102 | Authorized CloudFront distribution or OAI IDs |
| S3.C106_C110 | Authorized access point ARNs |
| S3.C123 | Authorized Batch Operations job role ARNs |
| S3.C146_C147 and S3.C167_C168 | Buckets requiring SSE-C, as a bucket name or `bucket/prefix/` for one path (one shared list, set in both rules) |
| S3.C150_C151 | Authorized IAM principals and canonical user IDs for bucket policies |
| S3.C155_C156 | Service-linked role ARNs a bucket policy Deny may exempt; each is authorized on every assessed bucket |
| S3.C159_C161 | Authorized bucket names and bucket-owner account IDs |
| S3.C171_C172 | Bucket names authorized to use ABAC: ABAC must be on for each of these and off everywhere else |
| S3.C174_C177 (allowlist mode) | Bucket names allowed to stay in the global namespace until they are replaced |

### Notes on specific rules

- The bucket, endpoint and organization policy rules count a Deny only when
  it applies to all principals, covers the actions and resources the control
  protects, and carries no other condition. A Deny limited to one role, one
  path or an extra condition leaves the rest open and does not satisfy the
  control. The notes below name two exceptions: the AWS service exemption on
  the transport Denies (S3.C1_C2, S3.C3_C5, S3.C6_C7) and a Deny on every
  service-linked role (S3.C155_C156). A Deny written with `NotResource`,
  `NotAction` or `NotPrincipal` is never counted.
- A `Resource` pattern is read the way IAM reads it, and it counts only when
  it leaves nothing out. For one bucket, `arn:aws:s3:::my-bucket/*`,
  `arn:aws:s3:::my-bucket*` and `arn:aws:s3:::*` cover every object;
  `arn:aws:s3:::my-bucket/logs/*` and `arn:aws:s3:::my-bucket/a*` do not.
  For an endpoint, `arn:aws:s3:::*` covers every bucket and object and
  `arn:aws:s3:::s*` does not. A wildcard also reaches a bucket whose name
  contains dots. An object key and a bucket name are never empty, so
  `arn:aws:s3:::my-bucket/?*` covers every object of the bucket and
  `arn:aws:s3:::?*` every bucket. A key prefix stays strict:
  `arn:aws:s3:::my-bucket/secure/?*` misses the key `secure/` itself.
- Condition operator names are case sensitive, so a Deny counts only under
  the exact name: `StringNotEquals`, `ArnLike`, `Null` or
  `ForAllValues:StringNotLike`, never `stringnotequals`. Action names and
  condition key names are not case sensitive. Where a control protects one
  action, an action pattern counts when it covers that action: for
  S3.C66_C67 and S3.C146_C147, `s3:Put*` and `s3:PutObj?ct` cover
  `s3:PutObject`, and `s3:PutObject?` does not.
- In Terraform, a policy written as `data.aws_iam_policy_document.<name>.json`
  or `.minified_json` is read from the data block with exactly that name. A bucket policy is read
  from `aws_s3_bucket_policy` and from the `policy` argument of
  `aws_s3_bucket`. Both write the one bucket policy, so when a configuration
  sets more than one, a grant in any of them is reported, and a rule that
  requires a Deny needs it in each. The data block, and a bucket policy or
  endpoint policy kept in another file, are found in any file of the same
  module (directory). A block declared in more than one file is read in
  each: a required Deny must be in all of them, and a grant in any of them is
  reported. A document that takes statements from a `dynamic "statement"`
  block or other policy documents is reported by S3.C23_C24, S3.C137_C102 and
  S3.C150_C151; a document with an override document cannot prove a Deny.
  In a Wiz IaC scan the data source arrives already resolved: a document
  with a `dynamic` block arrives as an empty policy, and statements from
  source or override documents are dropped. A rule that requires a Deny
  reports an empty policy. For the scan to read the policy, rewrite the whole
  document with every statement it generates written out and no `dynamic`
  block, or as JSON (a heredoc or `jsonencode`). S3.C23_C24,
  S3.C137_C102 and S3.C150_C151 report any policy whose statements they
  cannot read, including an empty one. They also match a resolved policy
  back to the documents of its module and report it when it comes from a
  document that takes source or override documents; when a plain document
  writes the same statements, the scan cannot tell them apart and the policy
  is not reported.
  `Effect` is case sensitive, so only `Deny` denies. An S3 VPC endpoint holds
  one policy, and its `policy` argument and an `aws_vpc_endpoint_policy`
  overwrite each other. When a configuration sets both, or more than one
  `aws_vpc_endpoint_policy`, S3.C3_C5, S3.C19_C20 and S3.C34_C36 need each of
  them to hold the full control, since only one applies; S3.C23_C24 reports a
  grant in any of them.
- **S3.C6_C7** requires BOTH transport protections on every bucket policy: a
  Deny on `aws:SecureTransport = false` AND a Deny on `s3:TlsVersion < 1.2`,
  each covering the bucket and every object in it. This is stricter than the
  AWS Config SSL-only rule, by design. The IfExists forms of both tests count.
  A Deny may also exempt AWS services with `aws:PrincipalIsAWSService` false,
  tested with `BoolIfExists`. Anonymous requests carry no such key, so under
  plain `Bool` the Deny skips them and is not counted. S3.C3_C5 reads the
  tests and the exemption the same way.
- **S3.C3_C5** requires BOTH transport protections on every S3 VPC endpoint
  policy, each for all principals and all S3 actions on every bucket and
  object. A request over plain HTTP carries no TLS version, so the TLS Deny
  alone does not stop it, and the transport Deny alone lets TLS below 1.2
  through. The control text joins the two with "or"; requiring both is a
  deliberate reading.
- **S3.C19_C20** counts the organization Deny only when it applies to all
  principals and all S3 actions on every bucket and object, with one
  organization test as its only condition. The operator must suit the key:
  `StringNotEquals` or `StringNotEqualsIfExists` on `aws:PrincipalOrgID` or
  `aws:PrincipalAccount`, which hold one value, and
  `ForAllValues:StringNotEquals` or `ForAllValues:StringNotLike` on
  `aws:PrincipalOrgPaths`, which holds a set. A `ForAnyValue:` test on
  `aws:PrincipalOrgPaths` is not counted: a principal outside any
  organization has no paths, so the test is false and the Deny lets it
  through. The allowlist mode compares each value in the Deny with the
  configured list as exact text, so list an org path pattern as written; the
  rule does not judge how broad a pattern is.
- **S3.C23_C24** accepts an Allow only on an authorized bucket ARN or on
  objects in that bucket, a key prefix included. A wildcard in the bucket
  name, and an Allow written with `NotResource`, are findings. In Terraform,
  a reference to an `aws_s3_bucket` resource or data source in the same
  module is read as the literal `bucket` name that block states, and an `arn`
  reference takes the partition of the endpoint's region. A generated name
  (`bucket_prefix`, or no `bucket`), a name from a variable and a reference
  to a block not in the module are not resolved by this source scan and are
  reported, as is an `arn` reference on an endpoint whose region is outside
  the `aws`, `aws-cn` and `aws-us-gov` partitions.
- **S3.C34_C36** counts the endpoint policy Denies only when they apply to
  all principals on every object and cover both `s3:PutObjectAcl` and
  `s3:PutObjectVersionAcl`, for the `public-read`, `public-read-write` and
  `authenticated-read` canned ACLs on `s3:x-amz-acl` (`StringEquals`,
  `StringLike` or their IfExists forms), and for each of the
  `s3:x-amz-grant-read`, `s3:x-amz-grant-read-acp`, `s3:x-amz-grant-write-acp`
  and `s3:x-amz-grant-full-control` headers naming the `AllUsers` or
  `AuthenticatedUsers` group (`StringLike` with a pattern that starts and ends
  with `*`, or `Null` false). Each test must be its statement's only
  condition. Statements may split actions, values and groups, and a Deny of
  both actions with no condition covers every form. An upload that sets an
  ACL needs `s3:PutObjectAcl` as well, so the Deny also stops uploads with a
  public ACL. An ACL sent in the request body is outside what these condition
  keys see; S3 Block Public Access, or ACLs disabled through Object Ownership,
  blocks that form.
- **S3.C106_C110** requires the access point Deny on the bucket's objects
  only. Covering the bucket ARN as well is accepted but not required, since
  bucket settings calls cannot go through an access point. The `Resource`
  pattern must leave no object out.
- **S3.C146_C147** accepts a Deny on the required path, on a wider pattern
  that contains it, or on the whole bucket. A Deny on part of the path, such
  as `my-bucket/secure/a*` or `my-bucket/secure/?*`, does not count.
- **S3.C137_C102** counts a CloudFront grant as approved only when every
  value is approved: each `aws:SourceArn` value must be the ARN of an
  authorized distribution, tested with `StringEquals`, `ArnEquals` or
  `ArnLike` and no wildcard, and each origin access identity principal must
  carry an authorized ID. A grant to the CloudFront service with no such test
  is reported. In Terraform, the ID of a distribution or identity created in
  the same configuration is not resolved by this source scan and is reported;
  an identity granted by a literal canonical user ID is not read.
- **S3.C159_C161** in Terraform needs the bucket owner stated as a literal
  `bucket_account_id` or `account_id`, and a referenced bucket must state a
  literal `bucket` name. Values not resolved by this source scan, such as
  `data.aws_caller_identity`, are reported.
- **S3.C167_C168** checks the bucket's `BlockedEncryptionTypes` default
  encryption setting (SSE-C blocked by default on new buckets since April
  2026). Buckets in the SSE-C-required set, including a bucket with a
  required path, must set it to `NONE`; every other bucket must block SSE-C.
  A bucket policy Deny does not count here: path-level enforcement is
  S3.C146_C147. The Terraform matcher needs an explicit
  `blocked_encryption_types` value, since without it the outcome depends on
  the bucket's age and the account's SSE-C history, which code cannot show.
- **S3.C140_C62** checks the bucket's default encryption, which applies to
  new objects uploaded without a key. It passes SSE-KMS or DSSE-KMS with a
  key ARN authorized for the bucket: from `authorized_kms_key_ids`, the list
  S3.C66_C67 uses, or only from the bucket's own entry in
  `authorized_kms_key_ids_by_bucket`. SSE-S3, `aws:kms` with no key (the AWS
  managed key `aws/s3`) and a key alias are reported; a bucket in
  `sse_s3_buckets` may keep SSE-S3. A key ID without an ARN is read as the
  key of the bucket's account and Region. Objects already stored and uploads
  that name their own key are not in the bucket settings: S3.C66_C67 denies
  other keys on upload, and an S3 Inventory report shows each object's
  encryption status. In Terraform, a bucket with no default encryption
  configuration is reported, since S3 then uses SSE-S3, and objects uploaded
  by `aws_s3_object`, `aws_s3_object_copy` or `aws_s3_bucket_object` are
  judged when they set their encryption. A key given by reference or as a
  key ID is left to the cloud check; encryption generated by a `dynamic`
  block is reported.
- **S3.C74_C75** assesses only the buckets in `worm_buckets`. Each must have
  Object Lock enabled with a default retention in its listed mode and for at
  least its `min_days`. A default in years counts 365 days per year, the
  conversion S3 uses for Object Lock condition keys. A default that only
  turns on an event hold is not in the data Wiz collects or in Terraform, so
  set `Days` or `Years` as well. The retention of objects already stored is
  not in the bucket settings. In Terraform, a bucket named only at apply is
  not judged, and a default generated by a `dynamic` block is reported.
- **S3.C134_C87 and S3.C134_C88** share one list of authorized replication
  routes. C87 flags replication on a bucket that is not on the list; C88
  checks each enabled rule of a listed bucket against its route: the target,
  the replica KMS key (with SSE-KMS objects replicated) or no replica key,
  the replica owner override, and Replication Time Control. The list replaces
  the earlier list of authorized destination ARNs: move existing values into
  it.
- **S3.C138_C92** lists authorized roles per source bucket: a role passes
  only on the buckets it is listed under, and a bucket that replicates with
  no entry fails. The map replaces the earlier flat list of role ARNs: move
  each role under the buckets that replicate with it. Listing every role
  under every bucket restores the earlier behavior but drops the per-bucket
  check.
- In Terraform, the replication rules (S3.C134_C87, S3.C134_C88,
  S3.C138_C92 and S3.C134_C117) read both
  `aws_s3_bucket_replication_configuration` and the inline
  `replication_configuration` block of `aws_s3_bucket`. Replication rules
  generated by a `dynamic` block cannot be read, so they are reported
  instead of passing: S3.C134_C87 reports them on a bucket that is not on
  its list and has no enabled rule written out, S3.C134_C88 on a bucket
  that is, and S3.C134_C117 on every bucket. S3.C134_C88 and S3.C134_C117
  also report a rule whose destination, or a block they check such as
  `metrics`, is generated by a `dynamic` block. S3.C138_C92 reports an
  inline `replication_configuration` generated by a `dynamic` block, since
  its role is then not in the source. Write these blocks out to have them
  checked. A `dynamic` block whose `for_each` is a literal empty list, map or
  set generates nothing and is ignored.
- In Terraform, other blocks generated by a `dynamic` block are reported
  instead of passing: S3.C135_C95 reports generated notification receivers,
  S3.C136_C97 a generated inventory destination, S3.C167_C168 blocked
  encryption types in a generated `rule`, and S3.C171_C172 a generated
  `abac_status` on any bucket. A `dynamic` block whose `for_each` is a
  literal empty list, map or set generates nothing and is ignored. Write
  these blocks out to have them checked.
- The Terraform rules skip a resource that is never created: a literal
  `count = 0`, or a `for_each` over a literal empty list, map or set. Such
  a resource is not judged, and it never counts as a setting another
  resource needs: a bucket whose only
  `aws_s3_bucket_server_side_encryption_configuration` (S3.C167_C168) or
  `aws_s3_bucket_abac` (S3.C171_C172) is never created is judged as having
  none. A bucket policy, endpoint policy or SCP attachment that is never
  created never counts as protection. A `count` or `for_each` set by a
  variable or any other expression is still judged.
- **S3.C135_C95** approves EventBridge delivery per bucket: a bucket that
  sends events to Amazon EventBridge fails unless it is on the EventBridge
  bucket list. Approving a bucket does not check where EventBridge rules
  forward its events.
- **S3.C150_C151** compares Allow grants to IAM principals with the
  authorized principal list, and grants to canonical user IDs with the
  canonical user list. That list is empty by default, so a canonical user
  grant is a finding until its ID is listed. An Allow written with
  `NotPrincipal` is a finding whatever it lists: it grants every principal
  except those it lists, so it cannot be shown to stay within the authorized
  list. In Terraform, an Allow that names no principal is read the same way,
  since a scan reads a `not_principals` statement as naming none.
- **S3.C155_C156** counts a bucket policy Deny for all principals on `s3:*`
  (or `*`), over the bucket and every object, when it reaches every
  service-linked role: with no `aws:PrincipalArn` test, or with an `ArnLike`,
  `ArnEquals` or `StringLike` test (or its IfExists form) whose pattern
  covers the service-linked roles of every account, such as
  `arn:aws:iam::*:role/aws-service-role/*` or
  `arn:aws:iam::*:*/AWSServiceRoleFor*`. A pattern for one account or one
  service does not count. Roles the Deny exempts (`ArnNotEquals`,
  `ArnNotLike`, `StringNotEquals`, `StringNotLike` or their IfExists forms)
  must be on the authorized list.
- The VPC endpoint rules evaluate every VPC endpoint in the tenant but skip
  endpoints of other services (scoped by service name ending `.s3`).
- **S3.C1_C2** has no cloud matcher: Wiz files SCPs under a policy type that
  every service shares, so the Terraform matcher judges the control. It
  judges the SCPs attached to each organization root together, across every
  file in the scan: both Denies must be attached to the same root, in one SCP
  or two, each on all S3 actions and every S3 resource (`*` or
  `arn:aws:s3:*`), with no other condition apart from the AWS service
  exemption (`aws:PrincipalIsAWSService` false, under `Bool` or
  `BoolIfExists`, since an SCP governs only the organization's signed
  requests). A Deny on `arn:aws:s3:::*` does not count, because a request
  through an access point names the access point ARN. A literal root ID and a
  reference to an `aws_organizations_organization` count as different roots.
  SCPs attached to an OU or an account are not judged, and a scan with no
  root attachment and no organization gives no result. Content the Terraform
  source does not show (a variable or a file) is reported.
- **S3.C123** has no Terraform matcher: Batch Operations jobs are runtime
  executions with no Terraform resource.
- **S3.C171_C172** has no cloud matcher: Wiz does not collect a bucket's ABAC
  status. ABAC is off by default, so an authorized bucket needs an
  `aws_s3_bucket_abac` that enables it, declared in the same `.tf` file as the
  bucket, which is the unit a Wiz IaC scan reads. Needs hashicorp/aws 6.23.0
  or later.
- **S3.C174_C177** recognises an account regional bucket by its name, which
  ends with `-<account id>-<region>-an`, since no S3 API returns a bucket's
  namespace. A bucket's namespace is fixed when it is created, so every
  existing global bucket is flagged until it is replaced. The universal mode
  ships enabled, so expect one finding per existing bucket on the first scan;
  to roll out gradually, use the allowlist mode and list the buckets awaiting
  replacement. Buckets in Middle East (Bahrain) and Middle East (UAE), where
  S3 offers no account regional namespace, are skipped. The Terraform matcher
  reads `bucket_namespace` (hashicorp/aws 6.37.0 or later).

---

## Self-verification

`terraform_test_samples/` contains pass and fail Terraform samples for every
rule with a Terraform matcher, in folders named to match the rule folders.
Upload a `_fail.tf` sample through your Wiz IaC scan (CLI or CI integration)
and confirm the corresponding rule produces a finding; the `_pass.tf` sample
should scan clean. Allowlist samples align with the shipped placeholder
values, so validate them before replacing the placeholders (or update the
samples to your values).
