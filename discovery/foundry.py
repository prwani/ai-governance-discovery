"""Foundry/OpenAI and hub-based model inventories, retaining native quota units."""

import json
from urllib.parse import quote

from discovery.azure import safe_url


COGNITIVE_VERSION = "2025-06-01"
ML_VERSION = "2024-10-01"


def context(resource, subscription):
    rid = resource["id"]
    parts = rid.split("/")
    return {
        "subscription_id": subscription["id"], "subscription_name": subscription["name"],
        "tenant_id": subscription["tenantId"],
        "resource_group": next((parts[i + 1] for i, part in enumerate(parts[:-1])
                                if part.lower() == "resourcegroups"), ""),
    }


def private_endpoint_summary(resource):
    """Keep connection state evidence without exporting user-supplied descriptions."""
    connections = []
    for connection in resource.get("properties", {}).get("privateEndpointConnections", []):
        if not isinstance(connection, dict):
            continue
        properties = connection.get("properties", {})
        state = properties.get("privateLinkServiceConnectionState", {})
        endpoint = properties.get("privateEndpoint", {})
        connections.append({
            "id": connection.get("id", ""),
            "private_endpoint_id": endpoint.get("id", ""),
            "group_ids": properties.get("groupIds", []),
            "status": state.get("status", ""),
            "actions_required": state.get("actionsRequired", ""),
        })
    return connections


def rai_policy_summary(policy):
    """Retain filter configuration but never export custom blocklist contents."""
    properties = policy.get("properties", {})
    return {
        "id": policy.get("id", ""),
        "name": policy.get("name", ""),
        "mode": properties.get("mode", ""),
        "base_policy_name": properties.get("basePolicyName", ""),
        "content_filters": [
            {key: item.get(key, "") for key in
             ("name", "source", "enabled", "blocking", "severityThreshold")}
            for item in properties.get("contentFilters", [])
            if isinstance(item, dict)
        ],
        "custom_blocklist_count": len(properties.get("customBlocklists", []))
        if isinstance(properties.get("customBlocklists", []), list) else "",
    }


def resource_row(resource, subscription, parent_id="", auth_resource=None):
    properties = resource.get("properties", {})
    auth_resource = resource if auth_resource is None else auth_resource
    disabled = auth_resource.get("properties", {}).get("disableLocalAuth")
    key_access = "unknown"
    if isinstance(disabled, bool):
        key_access = "disabled" if disabled else "allowed"
    endpoints = {key: safe_url(value) for key, value in properties.get("endpoints", {}).items()
                 if isinstance(value, str)}
    return {
        **context(resource, subscription),
        "id": resource["id"], "name": resource["name"], "type": resource.get("type", ""),
        "kind": resource.get("kind", ""), "location": resource.get("location", ""),
        "parent_id": parent_id, "endpoint": safe_url(properties.get("endpoint", "")),
        "endpoints": json.dumps(endpoints, sort_keys=True),
        "provisioning_state": properties.get("provisioningState", ""),
        "public_network_access": properties.get("publicNetworkAccess", ""),
        "disable_local_auth": disabled if isinstance(disabled, bool) else "",
        "key_based_access": key_access,
        "key_based_access_source_resource_id": auth_resource["id"],
        "hub_resource_id": properties.get("hubResourceId", ""),
        "private_endpoint_count": len(private_endpoint_summary(resource)),
        "private_endpoint_connections": json.dumps(
            private_endpoint_summary(resource), sort_keys=True),
    }


def token_limit(rules):
    """Use explicit token rules only; request limits and capacity are not TPM."""
    limits = []
    for rule in rules or []:
        if str(rule.get("key", "")).lower() not in ("token", "tokens"):
            continue
        count, period = rule.get("count"), rule.get("renewalPeriod")
        if isinstance(count, (int, float)) and isinstance(period, (int, float)) and period > 0:
            limits.append(count * 60 / period)
    return min(limits) if limits else ""


def deployment_row(deployment, account, subscription):
    properties = deployment.get("properties", {})
    model = properties.get("model", {})
    sku = deployment.get("sku", {})
    deployment_type = sku.get("name", properties.get("scaleSettings", {}).get("scaleType", ""))
    rules = properties.get("rateLimits", [])
    tpm = token_limit(rules)
    return {
        **context(account, subscription),
        "id": deployment["id"], "name": deployment["name"],
        "resource_id": account["id"], "account_id": account["id"],
        "location": account.get("location", ""),
        "model_name": model.get("name", ""), "model_version": model.get("version", ""),
        "model_format": model.get("format", ""), "model_publisher": model.get("publisher", ""),
        "deployment_type": deployment_type, "capacity": sku.get("capacity", ""),
        "capacity_unit": "PTU" if "provisioned" in deployment_type.lower() else "SKU capacity units",
        "current_capacity": properties.get("currentCapacity", ""),
        "allocated_tpm": tpm, "tpm_source": "properties.rateLimits" if tpm != "" else "",
        "endpoint": safe_url(account.get("properties", {}).get("endpoint", "")),
        "rate_limits": json.dumps(rules, sort_keys=True),
        "provisioning_state": properties.get("provisioningState", ""),
        "version_upgrade_option": properties.get("versionUpgradeOption", ""),
        "rai_policy_name": properties.get("raiPolicyName", ""),
    }


def collect_foundry(client, subscription):
    base = "/subscriptions/" + subscription["id"]
    resources, deployments = [], []
    accounts = client.list(base + "/providers/Microsoft.CognitiveServices/accounts", COGNITIVE_VERSION)
    for account in accounts:
        kind = account.get("kind", "").lower()
        if kind not in ("openai", "aiservices", "contentsafety"):
            continue
        policies = []
        policy_status = "not_applicable"
        if kind in ("openai", "aiservices"):
            previous_errors = len(getattr(client, "errors", ()))
            policies = [
                rai_policy_summary(policy) for policy in client.list(
                    account["id"] + "/raiPolicies", COGNITIVE_VERSION
                )
            ]
            policy_status = (
                "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
            )
        account_row = resource_row(account, subscription)
        account_row["rai_policies"] = json.dumps(policies, sort_keys=True)
        account_row["rai_policy_inventory_status"] = policy_status
        resources.append(account_row)
        if kind == "contentsafety":
            continue
        models = client.list(account["id"] + "/models", COGNITIVE_VERSION)
        for item in client.list(account["id"] + "/deployments", COGNITIVE_VERSION):
            row = deployment_row(item, account, subscription)
            matching_models = [m.get("model", m) for m in models
                               if m.get("model", m).get("name") == row["model_name"]
                               and m.get("model", m).get("version") == row["model_version"]
                               and m.get("model", m).get("format") == row["model_format"]]
            matching_skus = [sku for model in matching_models for sku in model.get("skus", [])
                             if sku.get("name", "").lower() == row["deployment_type"].lower()]
            if len(matching_skus) == 1:
                sku = matching_skus[0]
                per_unit = token_limit(sku.get("rateLimits", []))
                if per_unit != "" and "standard" in row["deployment_type"].lower():
                    row["tpm_per_capacity_unit"] = per_unit
                    row["tpm_per_capacity_unit_source"] = "account.models.skus.rateLimits"
                    if row["allocated_tpm"] == "" and isinstance(row["capacity"], (int, float)):
                        row["allocated_tpm"] = per_unit * row["capacity"]
                        row["tpm_source"] = "sku.capacity * account.models.skus.rateLimits"
            deployments.append(row)
        if account.get("kind", "").lower() == "aiservices":
            for project in client.list(account["id"] + "/projects", COGNITIVE_VERSION):
                resources.append(resource_row(project, subscription, account["id"], account))
    # Include legacy Azure AI hubs/projects and ML workspaces: models may be hosted
    # in a workspace even when its kind is not explicitly Hub/Project.
    workspaces = client.list(base + "/providers/Microsoft.MachineLearningServices/workspaces", ML_VERSION)
    for workspace in workspaces:
        resources.append(resource_row(workspace, subscription))
        for endpoint_type in ("onlineEndpoints", "batchEndpoints", "serverlessEndpoints"):
            for endpoint in client.list(workspace["id"] + "/" + endpoint_type, ML_VERSION):
                props = endpoint.get("properties", {})
                inference = props.get("inferenceEndpoint", {})
                url = safe_url(props.get("scoringUri", "") or inference.get("uri", ""))
                if endpoint_type == "serverlessEndpoints":
                    items = [endpoint]
                else:
                    items = client.list(endpoint["id"] + "/deployments", ML_VERSION)
                for deployment in items:
                    dp = deployment.get("properties", {})
                    model = dp.get("model", "")
                    model_id = model.get("modelId", "") if isinstance(model, dict) else model
                    sku = deployment.get("sku", {})
                    deployments.append({
                        **context(workspace, subscription),
                        "id": deployment["id"], "name": deployment["name"],
                        "resource_id": workspace["id"], "account_id": workspace["id"],
                        "location": workspace.get("location", ""),
                        "model_name": model_id, "model_version": "", "model_format": "",
                        "deployment_type": dp.get("endpointComputeType", endpoint_type),
                        "capacity": sku.get("capacity", dp.get("scaleSettings", {}).get("instanceCount", "")),
                        "capacity_unit": "instances" if endpoint_type != "serverlessEndpoints" else "",
                        "allocated_tpm": "",
                        "endpoint": url, "endpoint_id": endpoint["id"],
                        "endpoint_name": endpoint["name"],
                        "traffic": json.dumps(props.get("traffic", {}), sort_keys=True),
                        "provisioning_state": dp.get("provisioningState", ""),
                    })
    return resources, deployments


def collect_quotas(client, subscription, resources):
    rows = []
    regions = sorted({r["location"] for r in resources
                      if r["type"].lower() == "microsoft.cognitiveservices/accounts" and r["location"]})
    for region in regions:
        path = (f"/subscriptions/{subscription['id']}/providers/Microsoft.CognitiveServices/"
                f"locations/{quote(region, safe='')}/usages")
        for usage in client.list(path, COGNITIVE_VERSION):
            name = usage.get("name", {})
            rows.append({
                "subscription_id": subscription["id"], "subscription_name": subscription["name"],
                "tenant_id": subscription["tenantId"], "location": region,
                "usage_name": name.get("value", ""), "display_name": name.get("localizedValue", ""),
                "current_value": usage.get("currentValue", ""), "limit": usage.get("limit", ""),
                "unit": usage.get("unit", ""),
            })
    return rows
