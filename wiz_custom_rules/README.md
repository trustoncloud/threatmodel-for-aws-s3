# AWS S3 Customised CCRs for Wiz

23 Wiz custom configuration rules covering AWS S3 assurance controls from
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

25 controls, delivered as 27 rule folders (S3.C19_C20 and S3.C174_C177 ship
two modes).

| Rule | Severity | What it flags |
|---|---|---|
| S3.C49_C50 | Critical | Account-level S3 Block Public Access not fully enabled |
| S3.C99_C100 | Critical | Bucket policies that do not restrict access to authorized VPCs |
| S3.C1_C2 | High | Organization SCPs missing the Deny on unencrypted or older-TLS S3 traffic (Terraform-only) |
| S3.C6_C7 | High | Buckets whose policy does not deny unencrypted traffic and TLS below 1.2 |
| S3.C19_C20 | High | S3 VPC endpoints not restricted to authorized AWS Organizations or accounts |
| S3.C34_C36 | High | S3 VPC endpoints that do not block setting object ACLs to public |
| S3.C66_C67 | High | Buckets not enforcing the authorized KMS key(s) on uploads |
| S3.C106_C110 | High | Bucket policies that do not restrict access to authorized access points |
| S3.C146_C147 | High | SSE-C-required buckets not enforcing customer-key encryption on uploads |
| S3.C150_C151 | High | Bucket policies granting access to unauthorized IAM principals |
| S3.C167_C168 | High | SSE-C allowed on buckets that must block it, or blocked where required |
| S3.C3_C5 | Medium | S3 VPC endpoints whose policy does not deny insecure transport |
| S3.C23_C24 | Medium | S3 VPC endpoints granting access beyond authorized buckets |
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
| Controls | 25 |
| Rule folders (control x mode) | 27 |
| Cloud matchers | 23 (S3.C1_C2 and S3.C171_C172 are Terraform-only) |
| Terraform matchers | 24 (S3.C123 is cloud-only) |
| Cloud OPA tests passing | 248 of 248 |
| Terraform fixture checks passing | 52 of 52 |

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
| `bucket` | 17 |
| `vpcEndpoint` | S3.C3_C5, S3.C19_C20, S3.C23_C24, S3.C34_C36 (scoped to S3 endpoints by service name) |
| `s3AccessPoint` | S3.C159_C161 |
| `s3#job` | S3.C123 |

| Terraform resource | Rules |
|---|---|
| `aws_s3_bucket`, `aws_s3_bucket_policy` | the bucket-policy family (C7, C67, C100, C102, C110, C147, C151, C156) |
| `aws_s3_bucket_replication_configuration` | C87, C88, C92, C117 |
| `aws_s3_bucket_notification` / `aws_s3_bucket_inventory` | C95 / C97 |
| `aws_s3_account_public_access_block` | C50 |
| `aws_s3_bucket_server_side_encryption_configuration` | C168 |
| `aws_vpc_endpoint`, `aws_vpc_endpoint_policy` | C5, C20, C24, C36 |
| `aws_s3_access_point` | C161 |
| `aws_s3_bucket` (`bucket_namespace`) | C177 |
| `aws_s3_bucket_abac`, `aws_s3_bucket` | C172 |
| `aws_organizations_policy` | C2 |

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
│       └── metadata/
│           ├── metadata.json           Name, severity, native types, tags
│           ├── description.md
│           └── remediation.md
├── terraform_test_samples/             Sample .tf for self-validation,
│   └── S3.<parent>_<assurance>/        keyed to match the rule folders
│       └── test_<mode>_{pass,fail}.tf
├── main.tf                             Wiz Terraform module (reads Cloud_Configuration_Rules/)
├── providers.tf                        Wiz provider + auth instructions
├── versions.tf
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
| S3.C66_C67 | Authorized KMS key ARNs for uploads |
| S3.C134_C87 and S3.C134_C88 | Authorized replication routes: each source bucket, the destination bucket ARNs it may replicate to, and each route's replica KMS key, owner override and RTC (one shared list, set in both rules) |
| S3.C138_C92 | Authorized replication role ARNs |
| S3.C135_C95 | Authorized notification receivers (SNS, SQS, Lambda ARNs) |
| S3.C136_C97 | Authorized inventory destination bucket ARNs |
| S3.C99_C100 | Authorized VPC IDs |
| S3.C137_C102 | Authorized CloudFront distribution or OAI IDs |
| S3.C106_C110 | Authorized access point ARNs |
| S3.C123 | Authorized Batch Operations job role ARNs |
| S3.C146_C147 and S3.C167_C168 | Buckets requiring SSE-C, as a bucket name or `bucket/prefix/` for one path (one shared list, set in both rules) |
| S3.C150_C151 | Authorized IAM principals for bucket policies |
| S3.C155_C156 | Authorized service role ARNs |
| S3.C159_C161 | Authorized bucket names and bucket-owner account IDs |
| S3.C171_C172 | Bucket names authorized to use ABAC: ABAC must be on for each of these and off everywhere else |
| S3.C174_C177 (allowlist mode) | Bucket names allowed to stay in the global namespace until they are replaced |

### Notes on specific rules

- The bucket and endpoint policy rules count a Deny only when it applies to
  all principals, covers the actions and resources the control protects, and
  carries no other condition. A Deny limited to one role, one path or an
  extra condition leaves the rest open and does not satisfy the control.
- **S3.C6_C7** requires BOTH transport protections on every bucket policy: a
  Deny on `aws:SecureTransport = false` AND a Deny on `s3:TlsVersion < 1.2`,
  each covering the bucket and its objects. This is stricter than the AWS
  Config SSL-only rule, by design.
- **S3.C106_C110** requires the access point Deny on the bucket's objects
  only. Covering the bucket ARN as well is accepted but not required, since
  bucket settings calls cannot go through an access point.
- **S3.C167_C168** checks the bucket's `BlockedEncryptionTypes` default
  encryption setting (SSE-C blocked by default on new buckets since April
  2026). Buckets in the SSE-C-required set, including a bucket with a
  required path, must set it to `NONE`; every other bucket must block SSE-C.
  A bucket policy Deny does not count here: path-level enforcement is
  S3.C146_C147. The Terraform matcher needs an explicit
  `blocked_encryption_types` value, since without it the outcome depends on
  the bucket's age and the account's SSE-C history, which code cannot show.
- **S3.C134_C87 and S3.C134_C88** share one list of authorized replication
  routes. C87 flags replication on a bucket that is not on the list; C88
  checks each enabled rule of a listed bucket against its route: the target,
  the replica KMS key (with SSE-KMS objects replicated) or no replica key,
  the replica owner override, and Replication Time Control. The list replaces
  the earlier list of authorized destination ARNs: move existing values into
  it.
- The VPC endpoint rules evaluate every VPC endpoint in the tenant but skip
  endpoints of other services (scoped by service name ending `.s3`).
- **S3.C1_C2** has no cloud matcher: Wiz does not ingest SCPs as a scannable
  resource. The Terraform matcher enforces the control at build time.
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
