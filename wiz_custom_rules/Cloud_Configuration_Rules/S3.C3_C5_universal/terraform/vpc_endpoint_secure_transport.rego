package wiz

import data.generic.terraform as terraLib

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

ep_actions(stmt) := terraLib.getArray(stmt.Action)
ep_actions(stmt) := terraLib.getArray(stmt.Actions)

ep_resources(stmt) := terraLib.getArray(stmt.Resource)
ep_resources(stmt) := terraLib.getArray(stmt.Resources)

ep_all_actions(actions) { actions[_] == "*" }
ep_all_actions(actions) { actions[_] == "s3:*" }

ep_wildcard(v) { v == "*" }
ep_wildcard(v) { v[_] == "*" }

ep_json_everyone(stmt) { stmt.Principal == "*" }
ep_json_everyone(stmt) { ep_wildcard(stmt.Principal.AWS) }
ep_json_everyone(stmt) { ep_wildcard(stmt.Principals["*"]) }
ep_json_everyone(stmt) { ep_wildcard(stmt.Principals.AWS) }

ep_hcl_everyone(stmt) {
    p := terraLib.getArray(stmt.principals)[_]
    {"*", "AWS"}[p.type]
    ep_wildcard(p.identifiers)
}

ep_false(v) { v == "false" }
ep_false(v) { v == false }
ep_false(v) { v[_] == "false" }

ep_tls_floor_ok(v) { to_number(v) >= 1.2 }
ep_tls_floor_ok(v) { to_number(v[_]) >= 1.2 }

# The transport test must be the only condition; any extra key narrows the deny.
ep_sole_condition(stmt, operator) {
    count(stmt.Condition) == 1
    count(stmt.Condition[operator]) == 1
}

ep_json_qualifies(stmt, "transport") {
    ep_sole_condition(stmt, "Bool")
    ep_false(stmt.Condition.Bool["aws:SecureTransport"])
}

ep_json_qualifies(stmt, "tls") {
    ep_sole_condition(stmt, "NumericLessThan")
    ep_tls_floor_ok(stmt.Condition.NumericLessThan["s3:TlsVersion"])
}

ep_hcl_qualifies(c, "transport") {
    c.test == "Bool"
    c.variable == "aws:SecureTransport"
    ep_false(c.values)
}

ep_hcl_qualifies(c, "tls") {
    c.test == "NumericLessThan"
    c.variable == "s3:TlsVersion"
    ep_tls_floor_ok(c.values)
}

# Resources named by every Deny that enforces the given protection
# ("transport" or "tls") for all principals and all S3 actions.
ep_deny_resources(document, ep, name, kind) := json_rs | hcl_rs {
    policies := endpoint_policies(document, ep, name)
    json_rs := {r |
        stmt := ep_json_statements(policies[_])[_]
        stmt.Effect == "Deny"
        ep_all_actions(ep_actions(stmt))
        ep_json_everyone(stmt)
        ep_json_qualifies(stmt, kind)
        r := ep_resources(stmt)[_]
    }
    hcl_rs := {r |
        ds := document.data.aws_iam_policy_document[dsName]
        contains(policies[_], dsName)
        stmt := terraLib.getArray(ds.statement)[_]
        lower(stmt.effect) == "deny"
        ep_all_actions(terraLib.getArray(stmt.actions))
        ep_hcl_everyone(stmt)
        conds := terraLib.getArray(stmt.condition)
        count(conds) == 1
        ep_hcl_qualifies(conds[0], kind)
        r := terraLib.getArray(stmt.resources)[_]
    }
}

# --- Resource scope ---
# The endpoint reaches every bucket, so the deny must cover any bucket and any
# object; the sample ARNs stand in for them in each partition.
ep_partitions := {"aws", "aws-cn", "aws-us-gov"}

ep_scope_suffixes := {"sample-bucket", "sample-bucket/sample-object"}

ep_resource_reaches(r, suffix) {
    not contains(r, "${")
    glob.match(r, [], sprintf("arn:%s:s3:::%s", [ep_partitions[_], suffix]))
}

# Values that cannot be resolved statically are given the benefit of the
# doubt; a reference to one bucket is never all buckets.
ep_resource_reaches(r, suffix) {
    contains(r, "${")
    not regex.match(`\$\{aws_s3_bucket\.`, r)
}

ep_resource_reaches(r, suffix) {
    regex.match(`^(var|local|module|data)\.`, r)
}

ep_enforces(document, ep, name, kind) {
    reached := {suffix |
        r := ep_deny_resources(document, ep, name, kind)[_]
        suffix := ep_scope_suffixes[_]
        ep_resource_reaches(r, suffix)
    }
    count(reached) == count(ep_scope_suffixes)
}

# --- Logic ---
# Either protection satisfies the control. An S3 endpoint with no policy has
# the default full-access policy, so it fails too.
WizPolicy[result] {
    document := input.document[i]
    ep := document.resource.aws_vpc_endpoint[name]
    is_s3_service(ep.service_name)
    not ep_enforces(document, ep, name, "transport")
    not ep_enforces(document, ep, name, "tls")

    result := {
        "documentId": document.id,
        "resourceType": "aws_vpc_endpoint",
        "resourceName": terraLib.get_resource_name(ep, name),
        "searchKey": sprintf("aws_vpc_endpoint[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("S3 VPC endpoint '%s' must have a Deny for all principals and all S3 actions on all buckets and objects when aws:SecureTransport is false or s3:TlsVersion is below 1.2, with no other condition", [name]),
        "keyActualValue": sprintf("S3 VPC endpoint '%s' policy does not deny insecure transport at that scope", [name]),
        "resourceTags": terraLib.get_resource_tags(ep),
    }
}
