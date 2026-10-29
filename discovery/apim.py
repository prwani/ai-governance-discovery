"""API Management backends and evidence-based model routing relationships."""

import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

from discovery.azure import safe_url
from discovery.foundry import context


API_VERSION = "2024-05-01"


def arm_id(value):
    if not value:
        return ""
    value = value.strip()
    if value.lower().startswith("https://"):
        value = urlsplit(value).path
    return unquote(value).rstrip("/").lower()


def backend_row(backend, service, workspace_id=""):
    props = backend.get("properties", {})
    members = [
        {"id": member.get("id", ""), "priority": member.get("priority", ""),
         "weight": member.get("weight", "")}
        for member in props.get("pool", {}).get("services", [])
    ]
    return {
        "id": backend["id"], "name": backend["name"],
        "apim_id": service["id"], "apim_name": service["name"],
        "workspace_id": workspace_id, "url": safe_url(props.get("url", "")),
        "resource_id": props.get("resourceId", ""), "protocol": props.get("protocol", ""),
        "backend_type": props.get("type", "Single"), "pool_members": json.dumps(members),
        "title": props.get("title", ""),
    }


def api_summary(api, workspace_id=""):
    properties = api.get("properties", {})
    return {
        "id": api.get("id", ""),
        "name": api.get("name", ""),
        "workspace_id": workspace_id,
        "display_name": properties.get("displayName", ""),
        "path": properties.get("path", ""),
        "api_type": properties.get("type", ""),
        "api_revision": properties.get("apiRevision", ""),
        "api_version": properties.get("apiVersion", ""),
        "protocols": properties.get("protocols", []),
        "subscription_required": properties.get("subscriptionRequired", ""),
        "service_url": safe_url(properties.get("serviceUrl", "")),
    }


def product_summary(client, product, workspace_id=""):
    properties = product.get("properties", {})
    apis_path = product["id"] + "/apis"
    previous_errors = len(getattr(client, "errors", ()))
    apis = client.list(apis_path, API_VERSION)
    return {
        "id": product.get("id", ""),
        "name": product.get("name", ""),
        "workspace_id": workspace_id,
        "display_name": properties.get("displayName", ""),
        "approval_required": properties.get("approvalRequired", ""),
        "subscription_required": properties.get("subscriptionRequired", ""),
        "state": properties.get("state", ""),
        "api_ids": [api.get("id", "") for api in apis],
        "api_inventory_status": (
            "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
        ),
    }


def subscription_summary(subscription):
    properties = subscription.get("properties", {})
    return {
        "id": subscription.get("id", ""),
        "name": subscription.get("name", ""),
        "display_name": properties.get("displayName", ""),
        "owner_id": properties.get("ownerId", ""),
        "scope": properties.get("scope", ""),
        "state": properties.get("state", ""),
    }


def collect_apim(client, subscription):
    base = f"/subscriptions/{subscription['id']}/providers/Microsoft.ApiManagement/service"
    resources, backends = [], []
    for service in client.list(base, API_VERSION):
        props = service.get("properties", {})
        sku = service.get("sku", {}).get("name", "")
        workspace_supported = sku.lower() not in ("consumption", "developer", "basic", "standard")
        row = {
            **context(service, subscription),
            "id": service["id"], "name": service["name"], "location": service.get("location", ""),
            "sku": sku,
            "sku_capacity": service.get("sku", {}).get("capacity", ""),
            "gateway_url": safe_url(props.get("gatewayUrl", "")),
            "provisioning_state": props.get("provisioningState", ""),
            "virtual_network_type": props.get("virtualNetworkType", ""),
            "public_network_access": props.get("publicNetworkAccess", ""),
            "workspace_inventory_status": "attempted" if workspace_supported else "not_supported_by_tier",
        }
        previous_errors = len(getattr(client, "errors", ()))
        apis = [api_summary(api) for api in client.list(service["id"] + "/apis", API_VERSION)]
        api_status = "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
        previous_errors = len(getattr(client, "errors", ()))
        products = [product_summary(client, product) for product in
                    client.list(service["id"] + "/products", API_VERSION)]
        product_status = (
            "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
        )
        if any(product.get("api_inventory_status") == "partial" for product in products):
            product_status = "partial"
        previous_errors = len(getattr(client, "errors", ()))
        subscriptions = [subscription_summary(item) for item in
                         client.list(service["id"] + "/subscriptions", API_VERSION)]
        subscription_status = (
            "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
        )
        resources.append(row)
        previous_errors = len(getattr(client, "errors", ()))
        workspaces = client.list(service["id"] + "/workspaces", API_VERSION) \
            if workspace_supported else []
        workspace_status = (
            "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
        )
        for workspace in workspaces:
            workspace_id = workspace["id"]
            previous_errors = len(getattr(client, "errors", ()))
            apis.extend(
                api_summary(api, workspace_id)
                for api in client.list(workspace_id + "/apis", API_VERSION)
            )
            if len(getattr(client, "errors", ())) > previous_errors:
                api_status = "partial"
            previous_errors = len(getattr(client, "errors", ()))
            products.extend(
                product_summary(client, product, workspace_id)
                for product in client.list(workspace_id + "/products", API_VERSION)
            )
            if len(getattr(client, "errors", ())) > previous_errors or any(
                    product.get("api_inventory_status") == "partial"
                    for product in products):
                product_status = "partial"
        if workspace_status == "partial":
            api_status = product_status = "partial"
        row.update({
            "api_count": len(apis),
            "api_inventory": json.dumps(apis, sort_keys=True),
            "api_inventory_status": api_status,
            "product_count": len(products),
            "product_inventory": json.dumps(products, sort_keys=True),
            "product_inventory_status": product_status,
            "subscription_count": len(subscriptions),
            "subscription_inventory": json.dumps(subscriptions, sort_keys=True),
            "subscription_inventory_status": subscription_status,
        })
        for backend in client.list(service["id"] + "/backends", API_VERSION):
            backends.append(backend_row(backend, service))
        for workspace in workspaces:
            for backend in client.list(workspace["id"] + "/backends", API_VERSION):
                backends.append(backend_row(backend, service, workspace["id"]))
    return resources, backends


def hostname(url):
    if not url or "{{" in url:
        return ""
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def named_deployment(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    match = re.search(r"/(?:openai/)?deployments/([^/]+)", parts.path, flags=re.I)
    if match:
        return unquote(match.group(1))
    query = {key.lower(): value for key, value in parse_qs(parts.query).items()}
    for key in ("deployment", "deployment-name"):
        if query.get(key):
            return query[key][0]
    return ""


def resource_hosts(resource):
    endpoints = resource.get("endpoints", "{}")
    if isinstance(endpoints, str):
        endpoints = json.loads(endpoints)
    return {host for host in [hostname(resource.get("endpoint", "")),
                             *(hostname(value) for value in endpoints.values())] if host}


def mapping_row(backend, status, basis, resource=None, deployment=None):
    resource, deployment = resource or {}, deployment or {}
    return {
        "apim_id": backend["apim_id"], "apim_name": backend["apim_name"],
        "backend_id": backend["id"], "backend_name": backend["name"],
        "backend_url": backend.get("url", ""), "workspace_id": backend.get("workspace_id", ""),
        "foundry_resource_id": resource.get("id", ""),
        "foundry_resource_name": resource.get("name", ""),
        "deployment_id": deployment.get("id", ""), "deployment_name": deployment.get("name", ""),
        "match_status": status, "match_basis": basis,
    }


def map_single(backend, resources, deployments):
    rid = arm_id(backend.get("resource_id", ""))
    url = backend.get("url", "")
    host = hostname(url)
    exact = [r for r in resources if rid == arm_id(r["id"]) or
             rid.startswith(arm_id(r["id"]) + "/deployments/")]
    # Projects may share their parent account's DNS; do not infer a project by DNS.
    candidates = exact or [r for r in resources
                           if "/accounts/projects" not in r.get("type", "").lower()
                           and host and host in resource_hosts(r)]
    if len(candidates) > 1:
        return [mapping_row(backend, "ambiguous_resource", "Multiple resource matches")]
    name = named_deployment(url) or named_deployment(rid)
    if candidates:
        resource = candidates[0]
        if exact and host:
            other_hosts = {h for r in resources if arm_id(r["id"]) != arm_id(resource["id"])
                           for h in resource_hosts(r)}
            if host in other_hosts and host not in resource_hosts(resource):
                return [mapping_row(backend, "conflicting_evidence",
                                    "ARM resourceId and URL point to different resources")]
        basis = "backend.resourceId" if exact else "endpoint_hostname"
        scoped = [d for d in deployments if arm_id(d["resource_id"]) == arm_id(resource["id"])]
        if name:
            matching = [d for d in scoped if d["name"].lower() == name.lower()]
            if len(matching) == 1:
                return [mapping_row(backend, "deployment_confirmed", basis + "+deployment_name",
                                    resource, matching[0])]
            return [mapping_row(backend, "deployment_not_found" if not matching else "ambiguous_deployment",
                                basis + "+explicit_deployment=" + name, resource)]
        return [mapping_row(backend, "resource_only",
                            basis + "; backend does not identify a deployment", resource)]
    # ML scoring endpoints may not share the workspace hostname.
    endpoint_matches = [d for d in deployments if host and host == hostname(d.get("endpoint", ""))
                        and "/serverlessendpoints/" in d["id"].lower()]
    if len(endpoint_matches) == 1:
        deployment = endpoint_matches[0]
        resource = next((r for r in resources if arm_id(r["id"]) ==
                         arm_id(deployment["resource_id"])), {})
        return [mapping_row(backend, "deployment_confirmed", "serverless_endpoint_hostname",
                            resource, deployment)]
    endpoint_matches = [d for d in deployments if host and host == hostname(d.get("endpoint", ""))]
    if endpoint_matches:
        # Online endpoint traffic splitting/headers can choose a deployment at runtime.
        first = endpoint_matches[0]
        resource = next((r for r in resources if arm_id(r["id"]) ==
                         arm_id(first["resource_id"])), {})
        return [mapping_row(backend, "endpoint_only",
                            "endpoint_hostname; deployment selection is runtime-dependent", resource)]
    if "{{" in url:
        return [mapping_row(backend, "unresolved_named_value", "Backend URL contains named values")]
    return [mapping_row(backend, "unmatched", "No discovered resource/endpoint match")]


def map_backends(backends, resources, deployments):
    by_id = {arm_id(backend["id"]): backend for backend in backends}

    def resolve(backend, visited):
        key = arm_id(backend["id"])
        if key in visited:
            return [mapping_row(backend, "pool_cycle", "Cyclic backend pool reference")]
        members = backend.get("pool_members", "[]")
        if isinstance(members, str):
            members = json.loads(members)
        if not members:
            if backend.get("backend_type", "").lower() == "pool":
                return [mapping_row(backend, "empty_pool", "Backend pool has no members")]
            return map_single(backend, resources, deployments)
        rows = []
        for member in members:
            member_id = member.get("id", "")
            key = arm_id(member_id)
            if not key.startswith("/subscriptions/"):
                scope = backend.get("workspace_id") or backend["apim_id"]
                key = arm_id(scope + "/backends/" + member_id.rsplit("/", 1)[-1])
            target = by_id.get(key)
            mapped = resolve(target, visited | {arm_id(backend["id"])}) if target else [
                mapping_row(backend, "unresolved_pool_member", member_id)
            ]
            for row in mapped:
                row = dict(row)
                row.update({
                    "backend_id": backend["id"], "backend_name": backend["name"],
                    "backend_url": backend.get("url", ""),
                    "match_basis": "pool_member:" + member_id + ";" + row["match_basis"],
                    "pool_member_id": member_id,
                })
                rows.append(row)
        return rows

    return [row for backend in backends for row in resolve(backend, set())]
