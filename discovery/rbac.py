"""Read Azure RBAC assignments at or above each discovered Foundry scope."""

from urllib.parse import urlencode


API_VERSION = "2022-04-01"


def collect_role_assignments(client, resources, role_definitions=None):
    role_definitions = {} if role_definitions is None else role_definitions
    rows = []
    for resource in resources:
        scope = resource["id"].rstrip("/")
        path = scope + "/providers/Microsoft.Authorization/roleAssignments?" + urlencode({
            "$filter": "atScope()",
        })
        seen = set()
        for assignment in client.list(path, API_VERSION):
            assignment_id = assignment["id"]
            if assignment_id.lower() in seen:
                continue
            seen.add(assignment_id.lower())
            props = assignment.get("properties", {})
            definition_id = props.get("roleDefinitionId", "")
            definition_key = definition_id.lower()
            if definition_id and definition_key not in role_definitions:
                # Failed lookups are reported by the shared client; retain the ID
                # and avoid repeating the same denied lookup for every resource.
                role_definitions[definition_key] = client.get(definition_id, API_VERSION)
            definition = (role_definitions.get(definition_key) or {}).get("properties", {})
            assignment_scope = props.get("scope", "")
            rows.append({
                "foundry_resource_id": resource["id"],
                "foundry_resource_name": resource["name"],
                "foundry_resource_type": resource.get("type", ""),
                "subscription_id": resource["subscription_id"],
                "subscription_name": resource["subscription_name"],
                "tenant_id": resource["tenant_id"],
                "resource_group": resource["resource_group"],
                "assignment_id": assignment_id,
                "assignment_scope": assignment_scope,
                "assignment_relationship": (
                    "direct" if assignment_scope.rstrip("/").lower() == scope.lower()
                    else "inherited" if assignment_scope else "unknown"
                ),
                "principal_id": props.get("principalId", ""),
                "principal_type": props.get("principalType", ""),
                "role_definition_id": definition_id,
                "role_name": definition.get("roleName", ""),
                "role_type": definition.get("type", ""),
                "condition": props.get("condition", ""),
                "condition_version": props.get("conditionVersion", ""),
                "delegated_managed_identity_resource_id": props.get(
                    "delegatedManagedIdentityResourceId", ""),
                "created_on": props.get("createdOn", ""),
                "updated_on": props.get("updatedOn", ""),
            })
    return rows
