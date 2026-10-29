"""Subscription-scoped Azure Policy assignment metadata."""


API_VERSION = "2022-06-01"


def assignment_summary(assignment):
    properties = assignment.get("properties", {})
    parameters = properties.get("parameters", {})
    effect = parameters.get("effect", {})
    return {
        "id": assignment.get("id", ""),
        "name": assignment.get("name", ""),
        "display_name": properties.get("displayName", ""),
        "scope": properties.get("scope", ""),
        "policy_definition_id": properties.get("policyDefinitionId", ""),
        "enforcement_mode": properties.get("enforcementMode", ""),
        "not_scopes": properties.get("notScopes", []),
        "effect": effect.get("value", "") if isinstance(effect, dict) else "",
        "parameter_names": sorted(parameters),
    }


def collect_policy_assignments(client, subscription):
    path = (f"/subscriptions/{subscription['id']}/providers/"
            "Microsoft.Authorization/policyAssignments")
    return [
        assignment_summary(assignment)
        for assignment in client.list(path, API_VERSION)
    ]
