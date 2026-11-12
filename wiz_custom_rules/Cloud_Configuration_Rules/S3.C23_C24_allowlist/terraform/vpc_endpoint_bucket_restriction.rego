package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_buckets := {
    "arn:aws:s3:::authorized-bucket",
}

# --- Policy helpers ---
# Policies reach the matcher in three shapes: a JSON string with real IAM keys
# (jsonencode or heredoc), a JSON string with resolved data-source keys
# (Actions/Resources/Principals, condition values as arrays), or an unresolved
# reference to an aws_iam_policy_document data block (walked directly,
# lowercase names). The policy sits inline on the endpoint or on an associated
# aws_vpc_endpoint_policy.
is_s3_service(sn) { endswith(sn, ".s3") }

endpoint_policies(document, ep, name) := inline | assoc {
    inline := {ep.policy | is_string(ep.policy)}
    assoc := {p.policy |
        p := document.resource.aws_vpc_endpoint_policy[pn]
        terraLib.associatedResources(p, ep, pn, name, "vpc_endpoint_id", "id")
        is_string(p.policy)
    }
}

ep_json_statements(policy) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    doc := json.unmarshal(policy)
}

# Every statement of the endpoint's policies, tagged with the shape it came in.
ep_statements(document, ep, name) := json_stmts | hcl_stmts {
    policies := endpoint_policies(document, ep, name)
    json_stmts := {{"shape": "json", "stmt": stmt} | stmt := ep_json_statements(policies[_])[_]}
    hcl_stmts := {{"shape": "hcl", "stmt": stmt} |
        ds := document.data.aws_iam_policy_document[policy_data_source_name(policies[_])]
        stmt := terraLib.getArray(ds.statement)[_]
    }
}

ep_list(v) := v { is_array(v) } else := [v]

# effect is optional in the data source and defaults to Allow.
# A resolved data source carries no Effect when effect is left out.
ep_effect(s) := lower(object.get(s.stmt, "Effect", "Allow")) { s.shape == "json" }
ep_effect(s) := lower(object.get(s.stmt, "effect", "Allow")) { s.shape == "hcl" }

ep_resources(s) := array.concat(ep_list(object.get(s.stmt, "Resource", [])), ep_list(object.get(s.stmt, "Resources", []))) { s.shape == "json" }
ep_resources(s) := ep_list(object.get(s.stmt, "resources", [])) { s.shape == "hcl" }

has_any_policy(document, ep, name) {
    count(endpoint_policies(document, ep, name)) > 0
}

ep_allows(document, ep, name) := {s |
    s := ep_statements(document, ep, name)[_]
    ep_effect(s) == "allow"
}

# An Allow may name an authorized bucket, or objects in one. The bucket name
# must be written out in full, or come from a bucket in this file that states
# it: a wildcard there can reach other buckets, and a generated or computed
# name is not known in the source.
resource_authorized(res) {
    bucket := tocm_s3_arn_bucket(res)
    not regex.match(`[*?]`, bucket)
    p := tocm_arn_parts(res)
    tocm_arn_allowed(sprintf("arn:%s:s3:::%s", [p.partition, bucket]), authorized_buckets)
}

# A reference to a bucket in this file, by its exact address: a managed
# bucket (aws_s3_bucket.<name>) or a data source (data.aws_s3_bucket.<name>),
# through its id, bucket or arn. Interpolated ("${...}"), or bare as a resolved
# policy document gives it; a bucket name never holds "_", so a bare address
# is never a literal name.
tf_bucket_reference_pattern := `(\$\{\s*)?(data\.)?aws_s3_bucket\.([A-Za-z0-9_-]+)\.(id|bucket|arn)(\s*\})?`

tf_balanced(m) {
    m[1] == ""
    m[5] == ""
}

tf_balanced(m) {
    m[1] != ""
    m[5] != ""
}

tf_referenced_bucket(document, ref) := document.resource.aws_s3_bucket[ref.name] { ref.block == "" }
tf_referenced_bucket(document, ref) := document.data.aws_s3_bucket[ref.name] { ref.block == "data." }

# A bucket created more than once has no single name.
tf_repeated(b) { object.get(b, "count", null) != null }
tf_repeated(b) { object.get(b, "for_each", null) != null }

# The name the referenced bucket states. A generated name (bucket_prefix, or
# no bucket at all) and a name built from another value are not in the source.
tf_referenced_bucket_name(document, ref) := n {
    b := tf_referenced_bucket(document, ref)
    not tf_repeated(b)
    n := b.bucket
    is_string(n)
    n != ""
    not contains(n, "${")
}

# The partition of the endpoint, from the region in its service name: a
# request through the endpoint reaches buckets of that partition only. A region
# outside these partitions is not resolved.
tf_endpoint_region(ep) := m[1] {
    is_string(ep.service_name)
    m := regex.find_all_string_submatch_n(`^(?:cn\.)?com\.amazonaws\.([a-z0-9-]+)\.s3$`, ep.service_name, 1)[0]
}

tf_endpoint_partition(ep) := "aws-cn" {
    regex.match(`^cn-[a-z]+-[0-9]+$`, tf_endpoint_region(ep))
} else := "aws-us-gov" {
    regex.match(`^us-gov-[a-z]+-[0-9]+$`, tf_endpoint_region(ep))
} else := "aws" {
    regex.match(`^[a-z]{2}-[a-z]+-[0-9]+$`, tf_endpoint_region(ep))
}

# What a reference stands for: the bucket name, or for an ARN reference the
# bucket ARN in the partition of the endpoint.
tf_reference_value(document, ep, ref) := tf_referenced_bucket_name(document, ref) {
    ref.attribute != "arn"
} else := sprintf("arn:%s:s3:::%s", [tf_endpoint_partition(ep), tf_referenced_bucket_name(document, ref)]) {
    ref.attribute == "arn"
}

# The resource with its one bucket reference replaced by what it stands for.
# Any other interpolation leaves the value unresolved.
tf_resolved_resource(document, ep, r) := c {
    ms := regex.find_all_string_submatch_n(tf_bucket_reference_pattern, r, -1)
    count(ms) == 1
    m := ms[0]
    tf_balanced(m)
    not contains(replace(r, m[0], ""), "${")
    ref := {"block": m[2], "name": m[3], "attribute": m[4]}
    c := replace(r, m[0], tf_reference_value(document, ep, ref))
}

tf_resource_authorized(document, ep, r) {
    resource_authorized(r)
}

tf_resource_authorized(document, ep, r) {
    resource_authorized(tf_resolved_resource(document, ep, r))
}

tf_unauthorized_resources(document, ep, name) := {r |
    s := ep_allows(document, ep, name)[_]
    r := ep_resources(s)[_]
    not tf_resource_authorized(document, ep, r)
}

# An Allow written with NotResource grants every bucket except the listed ones.
ep_not_resource_elements := {"NotResource", "NotResources", "not_resources"}

ep_allows_by_exclusion(document, ep, name) {
    s := ep_allows(document, ep, name)[_]
    ep_not_resource_elements[k]
    object.get(s.stmt, k, null) != null
}

# An Allow always names its resources unless it is written with NotResource,
# and a resolved data source can leave not_resources out, so an Allow that
# names no resource is read the same way.
ep_allows_by_exclusion(document, ep, name) {
    s := ep_allows(document, ep, name)[_]
    count(ep_resources(s)) == 0
}

# --- Logic ---
# Fail 1: S3 endpoint with no policy defaults to full access.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not has_any_policy(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must limit access to authorized buckets: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' has no policy, so it can access any bucket", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 2: an Allow statement grants a resource outside the authorized buckets.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    res := tf_unauthorized_resources(document, ep, name)[_]

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' Allow statements must name only authorized buckets and their objects: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' allows access to '%s', which does not name an authorized bucket in this Terraform source", [name, res]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# Fail 3: an Allow statement uses NotResource.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    ep_allows_by_exclusion(document, ep, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' Allow statements must name authorized buckets in Resource: %v", [name, authorized_buckets]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' has an Allow written with NotResource, or with no Resource, which grants every bucket it does not list", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}

# The data block a policy names: data.aws_iam_policy_document.<name>.json,
# written with or without "${}".
policy_data_source_name(v) := m[1] {
    is_string(v)
    m := regex.find_all_string_submatch_n(`^\s*(?:\$\{)?\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:minified_)?json\s*\}?\s*$`, v, 1)[0]
}

# --- Matching helpers ---
# --- toc-match begin: arn v1 ---
# Parts of an AWS ARN; the resource keeps any further ":" characters.
tocm_arn_parts(arn) := {"partition": s[1], "service": s[2], "region": s[3], "account": s[4], "resource": r} {
    is_string(arn)
    s := split(trim_space(arn), ":")
    count(s) >= 6
    s[0] == "arn"
    s[1] != ""
    s[2] != ""
    r := concat(":", array.slice(s, 5, count(s)))
    r != ""
}

tocm_arn_equal(a, b) {
    tocm_arn_parts(a) == tocm_arn_parts(b)
}

tocm_arn_allowed(arn, allowed) {
    tocm_arn_equal(arn, allowed[_])
}

# Bucket name of an S3 bucket or object ARN (arn:aws:s3:::bucket[/key]).
tocm_s3_arn_bucket(arn) := b {
    p := tocm_arn_parts(arn)
    p.service == "s3"
    p.region == ""
    p.account == ""
    b := split(p.resource, "/")[0]
    b != ""
}
# --- toc-match end: arn v1 ---
