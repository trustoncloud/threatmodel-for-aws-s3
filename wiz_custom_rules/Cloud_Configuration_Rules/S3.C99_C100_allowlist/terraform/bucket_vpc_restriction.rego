package wiz

import data.generic.terraform as terraLib

# --- Configuration ---
# Keep in sync with the cloud matcher.
authorized_vpcs := {
    "vpc-0123456789abcdef0",
}

# --- Policy helpers ---
# Policies reach the matcher in three shapes: a JSON string with real IAM keys
# (jsonencode or heredoc), a JSON string with resolved data-source keys
# (Actions/Resources/Principals, condition values as arrays), or an unresolved
# reference to an aws_iam_policy_document data block (walked directly,
# lowercase names).

restriction_operators := {"stringnotequals", "stringnotequalsifexists"}

stmt_actions(stmt) := terraLib.getArray(stmt.Action)
stmt_actions(stmt) := terraLib.getArray(stmt.Actions)

stmt_resources(stmt) := terraLib.getArray(stmt.Resource)
stmt_resources(stmt) := terraLib.getArray(stmt.Resources)

json_covers_all_s3(stmt) { stmt_actions(stmt)[_] == "s3:*" }
json_covers_all_s3(stmt) { stmt_actions(stmt)[_] == "*" }

hcl_covers_all_s3(stmt) { terraLib.getArray(stmt.actions)[_] == "s3:*" }
hcl_covers_all_s3(stmt) { terraLib.getArray(stmt.actions)[_] == "*" }

wildcard(v) { v == "*" }
wildcard(v) { v[_] == "*" }

json_everyone(stmt) { stmt.Principal == "*" }
json_everyone(stmt) { wildcard(stmt.Principal.AWS) }
json_everyone(stmt) { wildcard(stmt.Principals["*"]) }
json_everyone(stmt) { wildcard(stmt.Principals.AWS) }

hcl_everyone(stmt) {
    p := terraLib.getArray(stmt.principals)[_]
    {"*", "AWS"}[p.type]
    wildcard(p.identifiers)
}

json_statements(pol) := array.concat(terraLib.getStatement(doc), terraLib.getArray(object.get(doc, "Statements", []))) {
    is_string(pol.policy)
    doc := json.unmarshal(pol.policy)
}

# A Deny for everyone on all S3 actions whose only condition is a
# StringNotEquals on aws:SourceVpc allows exactly the listed VPCs.
vpc_restrictions(document, pol) := json_rs | hcl_rs {
    json_rs := {{"resources": stmt_resources(stmt), "vpcs": terraLib.getArray(val)} |
        stmt := json_statements(pol)[_]
        stmt.Effect == "Deny"
        json_covers_all_s3(stmt)
        json_everyone(stmt)
        count(stmt.Condition) == 1
        conditions := stmt.Condition[operator]
        restriction_operators[lower(operator)]
        count(conditions) == 1
        val := conditions[key]
        lower(key) == "aws:sourcevpc"
    }
    hcl_rs := {{"resources": terraLib.getArray(stmt.resources), "vpcs": terraLib.getArray(c.values)} |
        is_string(pol.policy)
        ds := document.data.aws_iam_policy_document[dsName]
        contains(pol.policy, dsName)
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        hcl_covers_all_s3(stmt)
        hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        c := conds[0]
        restriction_operators[lower(c.test)]
        lower(c.variable) == "aws:sourcevpc"
    }
}

bucket_restrictions(document, bucket, name) := {r |
    pol := document.resource.aws_s3_bucket_policy[pName]
    terraLib.associatedResources(pol, bucket, pName, name, "bucket", "id")
    r := vpc_restrictions(document, pol)[_]
}

# --- Resource scope ---
# The deny must reach the bucket itself and every object in it; the sample
# object key stands in for any key.
scope_suffixes := {"bucket": "", "objects": "/sample-object"}

partitions := {"aws", "aws-cn", "aws-us-gov"}

literal_bucket_name(bucket) := n {
    n := bucket.bucket
    is_string(n)
    not contains(n, "${")
}

own_arn_pattern(name) := sprintf(`^(\$\{aws_s3_bucket\.%s\.arn\}|aws_s3_bucket\.%s\.arn|arn:[^:]*:s3:::(?:\$\{)?aws_s3_bucket\.%s\.(id|bucket)\}?)(.*)$`, [name, name, name])

resource_reaches(r, bucket, name, target) {
    r == "*"
}

# A reference to this bucket's ARN or name, interpolated or bare: judge
# whatever follows it.
resource_reaches(r, bucket, name, target) {
    m := regex.find_all_string_submatch_n(own_arn_pattern(name), r, 1)[0]
    glob.match(concat("", ["x", m[3]]), [], concat("", ["x", scope_suffixes[target]]))
}

resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    n := literal_bucket_name(bucket)
    glob.match(r, [], sprintf("arn:%s:s3:::%s%s", [partitions[_], n, scope_suffixes[target]]))
}

# Values that cannot be resolved statically (a generated bucket name, variables,
# locals, module outputs) are given the benefit of the doubt.
resource_reaches(r, bucket, name, target) {
    not contains(r, "${")
    not literal_bucket_name(bucket)
}

resource_reaches(r, bucket, name, target) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

resource_reaches(r, bucket, name, target) {
    regex.match(`^(var|local|module|data)\.`, r)
}

has_restriction(document, bucket, name) {
    reached := {target |
        r := bucket_restrictions(document, bucket, name)[_]
        scope_suffixes[target]
        resource_reaches(r.resources[_], bucket, name, target)
    }
    count(reached) == count(scope_suffixes)
}

allowed_vpcs(document, bucket, name) := {vpc |
    vpc := bucket_restrictions(document, bucket, name)[_].vpcs[_]
}

# --- Logic ---
# Fail 1: no VPC restriction on the bucket at the required scope.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    not has_restriction(document, bucket, name)

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("bucket '%s' must have a bucket policy Deny for all principals and all S3 actions on the bucket and its objects whose only condition is StringNotEquals on aws:SourceVpc, listing only authorized VPCs: %v", [name, authorized_vpcs]),
        "keyActualValue": sprintf("bucket '%s' has no bucket policy restricting access to authorized VPCs at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}

# Fail 2: a restriction exists but allows a VPC outside the authorized set.
WizPolicy[result] {
    document := input.document[i]
    bucket := document.resource.aws_s3_bucket[name]
    unauth := allowed_vpcs(document, bucket, name) - authorized_vpcs
    count(unauth) > 0

    result := {
        "documentId": document.id,
        "resourceType": "aws_s3_bucket",
        "resourceName": terraLib.get_resource_name(bucket, name),
        "searchKey": sprintf("aws_s3_bucket[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("bucket '%s' policy must only allow authorized VPCs: %v", [name, authorized_vpcs]),
        "keyActualValue": sprintf("bucket '%s' policy allows unauthorized VPC(s): %v", [name, unauth]),
        "resourceTags": terraLib.get_resource_tags(bucket),
    }
}
