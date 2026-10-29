#!/usr/bin/env python3
"""Generate an offline HTML governance report from a single scanner output directory."""

import argparse
import csv
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import sys


REQUIRED_FILES = (
    "foundry_resources", "model_deployments", "apim_resources",
    "apim_foundry_mappings", "foundry_role_assignments", "scan_errors",
)
INSIGHT_FILES = ("model_usage", "model_retirements")
RESOURCE_COLUMNS = [
    ("subscription_name", "Subscription name"),
    ("resource_group", "Resource group name"),
    ("name", "Foundry resource name"),
]
PILLARS = (
    "#1 AI CoE and Governance",
    "#2 AI Landing Zones",
    "#3 AgentOps",
    "#4 AI Security & Observability",
    "#5 Solution Optimisation",
    "#6 Agent Architectures",
)


SECTION_PILLARS = {
    "Azure Policy assignments": PILLARS[0],
    "Foundry resources with user or service-principal role assignments": PILLARS[0],
    "Model deployments past or nearing scheduled retirement": PILLARS[0],
    "Model retirement matches requiring verification": PILLARS[0],
    "Foundry resources with public access enabled": PILLARS[1],
    "API Management resources with public access enabled": PILLARS[1],
    "Private endpoint connections": PILLARS[1],
    "Diagnostic settings coverage": PILLARS[1],
    "Model deployments without a confirmed API Management backend mapping": PILLARS[2],
    "Model deployments with zero successful requests": PILLARS[2],
    "Model usage requiring verification": PILLARS[2],
    "Foundry RAI policy and deployment configuration": PILLARS[3],
    "Foundry resources with key-based access enabled": PILLARS[3],
    "APIM APIs, products, and subscriptions": PILLARS[5],
    "APIM backend routing evidence": PILLARS[5],
    "Foundry agent definitions and tool connections": PILLARS[5],
    "Regional AI quota usage": PILLARS[4],
}


def load_inventory(directory):
    tables = {}
    for name in REQUIRED_FILES:
        with (directory / (name + ".csv")).open(newline="", encoding="utf-8") as handle:
            tables[name] = list(csv.DictReader(handle))
    for name in INSIGHT_FILES:
        path = directory / (name + ".csv")
        if path.exists():
            with path.open(newline="", encoding="utf-8") as handle:
                tables[name] = list(csv.DictReader(handle))
    tables["summary"] = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    return tables


def normalize(value):
    return value.rstrip("/").lower()


def _json_list(value):
    if not value:
        return []
    parsed = json.loads(value) if isinstance(value, str) else value
    if not isinstance(parsed, list):
        raise ValueError("Inventory field must contain a JSON array")
    return parsed


def build_sections(tables):
    resources = tables["foundry_resources"]
    public = [row for row in resources if row.get("public_network_access", "").lower() == "enabled"]
    key_enabled = [row for row in resources if row.get("key_based_access", "").lower() == "allowed"]
    apim_public = [row for row in tables["apim_resources"]
                   if row.get("public_network_access", "").lower() == "enabled"]
    # Group assignments for readability while retaining every role and scope.
    principals = {}
    for assignment in tables["foundry_role_assignments"]:
        if assignment.get("principal_type", "").lower() not in ("user", "serviceprincipal"):
            continue
        key = (normalize(assignment["foundry_resource_id"]),
               assignment["principal_id"].lower())
        if key not in principals:
            principals[key] = {
                "subscription_name": assignment["subscription_name"],
                "resource_group": assignment["resource_group"],
                "name": assignment["foundry_resource_name"],
                "principal_id": assignment["principal_id"],
                "principal_type": assignment["principal_type"],
                "roles": set(), "assignments": set(),
            }
        row = principals[key]
        row["roles"].add(assignment.get("role_name") or assignment.get("role_definition_id", ""))
        details = (assignment.get("role_name") or assignment.get("role_definition_id", ""))
        details += " | " + assignment.get("assignment_relationship", "")
        details += " | " + assignment.get("assignment_scope", "")
        if assignment.get("condition"):
            details += " | condition: " + assignment["condition"]
        row["assignments"].add(details)
    for row in principals.values():
        row["roles"] = "\n".join(sorted(row["roles"]))
        row["assignments"] = "\n".join(sorted(row["assignments"]))

    mappings = tables["apim_foundry_mappings"]
    confirmed = {normalize(row["deployment_id"]) for row in mappings
                 if row.get("match_status") == "deployment_confirmed" and row.get("deployment_id")}
    candidates = {}
    for mapping in mappings:
        if mapping.get("foundry_resource_id") and mapping.get("match_status") != "deployment_confirmed":
            candidates.setdefault(normalize(mapping["foundry_resource_id"]), set()).add(
                mapping["apim_name"] + " / " + mapping["backend_name"] +
                " (" + mapping["match_status"] + ")"
            )
    unmapped = []
    for deployment in tables["model_deployments"]:
        if normalize(deployment["id"]) in confirmed:
            continue
        row = dict(deployment)
        row["foundry_name"] = next(
            (r["name"] for r in resources
             if normalize(r["id"]) == normalize(deployment["resource_id"])),
            deployment["resource_id"],
        )
        evidence = candidates.get(normalize(deployment["resource_id"]), set())
        row["mapping_status"] = ("Account/endpoint backend exists; deployment unconfirmed"
                                 if evidence else "No confirmed backend mapping found")
        row["related_backends"] = "\n".join(sorted(evidence))
        unmapped.append(row)
    sections = [
        ("Foundry resources with public access enabled", public, RESOURCE_COLUMNS,
         "Explicit publicNetworkAccess=Enabled only. This permits public networking configuration; "
         "firewalls and authentication may still restrict access. Projects without their own setting "
         "are not assumed public."),
        ("Foundry resources with key-based access enabled", key_enabled, RESOURCE_COLUMNS,
         "Explicit key_based_access=allowed only. Project rows reflect their parent account's "
         "authentication setting."),
        ("API Management resources with public access enabled", apim_public,
         RESOURCE_COLUMNS[:2] + [("name", "API Management resource name")],
         "Explicit publicNetworkAccess=Enabled only. A public gateway URL alone is not evidence "
         "that public access is enabled."),
        ("Foundry resources with user or service-principal role assignments",
         list(principals.values()), RESOURCE_COLUMNS + [
             ("principal_type", "Principal type"), ("principal_id", "Principal object ID"),
             ("roles", "Assigned roles"), ("assignments", "Role / relationship / scope / condition"),
         ],
         "Direct and inherited User/ServicePrincipal RBAC assignments, grouped by resource and "
         "principal. These assignments are not proof of model inference access: some roles apply "
         "only to unrelated services or management actions. Conditions, deny assignments and network "
         "rules may restrict access. Managed identities are also ServicePrincipal objects. Group "
         "membership, PIM eligibility and directory profiles were not queried."),
        ("Model deployments without a confirmed API Management backend mapping", unmapped,
         RESOURCE_COLUMNS[:2] + [
             ("foundry_name", "Foundry resource name"), ("name", "Deployment name"),
             ("model_name", "Model"), ("deployment_type", "Deployment type"),
             ("allocated_tpm", "Allocated TPM"), ("mapping_status", "Mapping evidence"),
             ("related_backends", "Related account/endpoint backends"),
         ],
         "Absence of a confirmed deployment-level mapping is not proof that a deployment bypasses "
         "APIM. Account-only backends, policies, runtime model selection and unresolved named values "
         "may route to it. Only explicit confirmed deployment mappings are excluded from this list."),
    ]
    deployment_columns = RESOURCE_COLUMNS[:2] + [
        ("foundry_name", "Foundry resource name"), ("deployment_name", "Deployment name"),
        ("model_name", "Model"), ("model_version", "Model version"),
    ]

    def with_resource_names(rows):
        resource_names = {normalize(r["id"]): r["name"] for r in resources}
        return [{**row, "foundry_name": resource_names.get(normalize(row.get("resource_id", "")), "")}
                for row in rows]

    usage = with_resource_names(tables.get("model_usage", []))
    zero_success = [row for row in usage if row.get("usage_status") == "zero_successful_requests"]
    unknown_usage = [row for row in usage if row.get("usage_status") not in
                     ("active", "zero_successful_requests")]
    usage_note = (
        "Both 7- and 30-day windows use Azure Monitor deployment-level metrics. "
        "Zero successful requests is a review candidate, not proof of no attempts: failures are "
        "shown separately. Missing telemetry, unsupported metrics and unavailable permissions are "
        "unknown, never zero. New or recreated deployments may have less than a full window of history. "
        f"Unknown/unsupported deployment-window rows: {len(unknown_usage)}."
    )
    if "model_usage" not in tables:
        usage_note += " Usage collection was not included in this scan; regenerate the inventory."
    sections.append((
        "Model deployments with zero successful requests", zero_success,
        deployment_columns + [
            ("window_days", "Window (days)"), ("successful_requests", "Successful requests"),
            ("failed_requests", "Failed attempts"), ("other_requests", "Unclassified attempts"),
            ("prompt_tokens", "Prompt tokens"), ("completion_tokens", "Completion tokens"),
            ("notes", "Coverage notes"),
        ], usage_note,
    ))
    if unknown_usage:
        sections.append((
            "Model usage requiring verification", unknown_usage,
            deployment_columns + [
                ("window_days", "Window (days)"), ("usage_status", "Collection status"),
                ("total_requests", "Recorded requests"), ("failed_requests", "Failed attempts"),
                ("notes", "Coverage notes"),
            ], "These rows are not classified as inactive. Check metric support, data availability "
            "and access permissions before making deployment decisions.",
        ))
    retirements = with_resource_names(tables.get("model_retirements", []))
    upcoming = [row for row in retirements if row.get("retirement_status") in
                ("past_retirement_date", "retiring_soon")]
    unresolved = [row for row in retirements if row.get("retirement_status") in
                  ("ambiguous", "schedule_unavailable", "not_listed", "version_not_listed")]
    retirement_note = (
        "Exact model/version comparison against Microsoft's published retirement schedule. "
        f"Upcoming warning window: {tables['summary'].get('retirement_warning_days', 90)} days. "
        "Past dates mean the published retirement date has passed, not that a live endpoint was tested. "
        f"Unresolved or unlisted deployments: {len(unresolved)}. "
        "An unlisted model is not evidence of unlimited support; consult its publisher."
    )
    if "model_retirements" not in tables:
        retirement_note += " Retirement collection was not included in this scan; regenerate the inventory."
    sections.append((
        "Model deployments past or nearing scheduled retirement", upcoming,
        deployment_columns + [
            ("lifecycle", "Published lifecycle"), ("retirement_date", "Retirement date"),
            ("days_to_retirement", "Days until retirement"), ("retirement_status", "Schedule status"),
            ("replacement", "Suggested replacement"), ("notes", "Notes"),
            ("source_url", "Schedule source"),
        ], retirement_note,
    ))
    if unresolved:
        sections.append((
            "Model retirement matches requiring verification", unresolved,
            deployment_columns + [
                ("retirement_status", "Match status"), ("notes", "Evidence / notes"),
                ("source_url", "Schedule source"),
            ], "Conflicting dates, absent exact versions and unavailable source data are not "
            "treated as healthy matches. Full results and retrieval timestamps are in model_retirements.csv.",
        ))

    policy_rows = []
    for subscription in tables.get("subscriptions", []):
        assignments = _json_list(subscription.get("policy_assignments"))
        if not assignments:
            policy_rows.append({
                "subscription_name": subscription.get("subscription_name", ""),
                "display_name": ("No assignments reported"
                                 if subscription.get("policy_assignment_status") == "complete"
                                 else subscription.get("policy_assignment_status", "Not collected")),
                "policy_definition_id": "",
                "scope": "",
                "enforcement_mode": "",
                "effect": "",
                "parameter_names": "",
            })
        for assignment in assignments:
            policy_rows.append({
                "subscription_name": subscription.get("subscription_name", ""),
                "display_name": assignment.get("display_name", ""),
                "policy_definition_id": assignment.get("policy_definition_id", ""),
                "scope": assignment.get("scope", ""),
                "enforcement_mode": assignment.get("enforcement_mode", ""),
                "effect": assignment.get("effect", ""),
                "parameter_names": ", ".join(assignment.get("parameter_names", [])),
                "collection_status": subscription.get("policy_assignment_status", ""),
            })
        if not assignments:
            policy_rows[-1]["collection_status"] = subscription.get(
                "policy_assignment_status", "Not collected")
    sections.append((
        "Azure Policy assignments", policy_rows, [
            ("subscription_name", "Subscription"), ("display_name", "Assignment"),
            ("policy_definition_id", "Policy definition"), ("scope", "Scope"),
            ("enforcement_mode", "Enforcement mode"), ("effect", "Effect"),
            ("parameter_names", "Configured parameter names"),
            ("collection_status", "Collection status"),
        ],
        "Subscription-scoped assignment inventory. Parameter values are intentionally excluded; "
        "management-group inheritance and compliance state are not calculated.",
    ))

    private_endpoints = []
    for resource in resources:
        has_inventory = "private_endpoint_connections" in resource
        connections = _json_list(resource.get("private_endpoint_connections"))
        if not connections:
            if not has_inventory:
                status = "Not collected"
            elif resource.get("private_endpoint_count") == "":
                status = "Unknown"
            else:
                status = "No connection reported"
            private_endpoints.append({
                "subscription_name": resource.get("subscription_name", ""),
                "resource_group": resource.get("resource_group", ""),
                "name": resource.get("name", ""),
                "private_endpoint_id": "",
                "status": status,
                "group_ids": "",
                "actions_required": "",
            })
        for connection in connections:
            private_endpoints.append({
                "subscription_name": resource.get("subscription_name", ""),
                "resource_group": resource.get("resource_group", ""),
                "name": resource.get("name", ""),
                "private_endpoint_id": connection.get("private_endpoint_id", ""),
                "status": connection.get("status", "Unknown"),
                "group_ids": ", ".join(connection.get("group_ids", [])),
                "actions_required": connection.get("actions_required", ""),
            })
    sections.append((
        "Private endpoint connections", private_endpoints, [
            ("subscription_name", "Subscription"), ("resource_group", "Resource group"),
            ("name", "AI resource"), ("private_endpoint_id", "Private endpoint"),
            ("status", "Connection state"), ("group_ids", "Group IDs"),
            ("actions_required", "Actions required"),
        ],
        "Connection configuration only; an approved connection does not confirm private DNS, "
        "routing, or end-to-end reachability. Older scans without these fields are marked not collected.",
    ))

    diagnostics = []
    for kind, inventory in (("Foundry/AI", resources),
                            ("API Management", tables["apim_resources"])):
        for resource in inventory:
            has_inventory = "diagnostic_settings" in resource
            settings = _json_list(resource.get("diagnostic_settings"))
            collection_status = resource.get("diagnostic_settings_status", "")
            if not settings:
                if not has_inventory:
                    summary = "Not collected"
                elif collection_status == "partial":
                    summary = "Collection partial; result may be incomplete"
                elif collection_status == "complete":
                    summary = "No diagnostic setting reported"
                else:
                    summary = "Unknown"
                diagnostics.append({
                    "resource_type": kind,
                    "subscription_name": resource.get("subscription_name", ""),
                    "resource_group": resource.get("resource_group", ""),
                    "name": resource.get("name", ""),
                    "setting_name": "",
                    "destinations": summary,
                    "enabled_logs": "",
                    "enabled_metrics": "",
                })
            for setting in settings:
                destinations = ", ".join(setting.get("destination_types", []))
                if collection_status == "partial":
                    destinations = "; ".join(filter(None, [
                        destinations, "Collection partial",
                    ]))
                diagnostics.append({
                    "resource_type": kind,
                    "subscription_name": resource.get("subscription_name", ""),
                    "resource_group": resource.get("resource_group", ""),
                    "name": resource.get("name", ""),
                    "setting_name": setting.get("name", ""),
                    "destinations": destinations,
                    "enabled_logs": ", ".join(setting.get("enabled_log_categories", [])),
                    "enabled_metrics": ", ".join(setting.get("enabled_metric_categories", [])),
                })
    sections.append((
        "Diagnostic settings coverage", diagnostics, [
            ("resource_type", "Resource type"), ("subscription_name", "Subscription"),
            ("resource_group", "Resource group"), ("name", "Resource"),
            ("setting_name", "Setting"), ("destinations", "Configured destinations"),
            ("enabled_logs", "Enabled log categories"),
            ("enabled_metrics", "Enabled metric categories"),
        ],
        "Shows configured diagnostic destinations and enabled categories for discovered Foundry/AI "
        "and APIM resources. It does not confirm delivery, retention, or access at the destination.",
    ))

    rai_rows = []
    for resource in resources:
        collection_status = resource.get("rai_policy_inventory_status", "")
        policies = _json_list(resource.get("rai_policies"))
        if not policies and collection_status:
            rai_rows.append({
                "subscription_name": resource.get("subscription_name", ""),
                "resource_group": resource.get("resource_group", ""),
                "resource_name": resource.get("name", ""),
                "policy_name": ("No account RAI policies reported"
                                if collection_status == "complete" else collection_status),
                "mode": "",
                "base_policy_name": "",
                "content_filters": "",
                "custom_blocklist_count": "",
            })
        for policy in policies:
            filters = _json_list(policy.get("content_filters", []))
            rai_rows.append({
                "subscription_name": resource.get("subscription_name", ""),
                "resource_group": resource.get("resource_group", ""),
                "resource_name": resource.get("name", ""),
                "policy_name": policy.get("name", ""),
                "mode": policy.get("mode", ""),
                "base_policy_name": policy.get("base_policy_name", ""),
                "content_filters": "; ".join(
                    f"{item.get('name', '')}: enabled={item.get('enabled', '')}, "
                    f"blocking={item.get('blocking', '')}, "
                    f"severity={item.get('severityThreshold', '')}"
                    for item in filters
                ),
                "custom_blocklist_count": policy.get("custom_blocklist_count", ""),
                "collection_status": collection_status,
            })
    for deployment in tables["model_deployments"]:
        if deployment.get("rai_policy_name"):
            rai_rows.append({
                "subscription_name": deployment.get("subscription_name", ""),
                "resource_group": deployment.get("resource_group", ""),
                "resource_name": deployment.get("resource_id", ""),
                "policy_name": deployment.get("rai_policy_name", ""),
                "mode": "Deployment binding",
                "base_policy_name": "",
                "content_filters": "",
                "custom_blocklist_count": "",
                "collection_status": "",
            })
    sections.append((
        "Foundry RAI policy and deployment configuration", rai_rows, [
            ("subscription_name", "Subscription"), ("resource_group", "Resource group"),
            ("resource_name", "AI resource / deployment scope"), ("policy_name", "Policy"),
            ("mode", "Mode"), ("base_policy_name", "Base policy"),
            ("content_filters", "Content-filter settings"),
            ("custom_blocklist_count", "Custom blocklists (count only)"),
            ("collection_status", "Collection status"),
        ],
        "Displays account policy configuration and deployment policy references where returned by ARM. "
        "Custom blocklist contents are never included; a missing policy row is not proof that filtering "
        "is disabled or absent at another enforcement layer.",
    ))

    apim_inventory = []
    for service in tables["apim_resources"]:
        for kind, field in (("API", "api_inventory"), ("Product", "product_inventory"),
                            ("Subscription", "subscription_inventory")):
            inventory_available = field in service
            entries = _json_list(service.get(field))
            status_key = field.removesuffix("_inventory") + "_inventory_status"
            inventory_status = service.get(status_key, "")
            if not entries:
                if not inventory_available:
                    summary = "Not collected"
                elif inventory_status == "partial":
                    summary = "Collection partial; result may be incomplete"
                elif inventory_status == "complete":
                    summary = "No records reported"
                else:
                    summary = "Unknown"
                apim_inventory.append({
                    "subscription_name": service.get("subscription_name", ""),
                    "resource_group": service.get("resource_group", ""),
                    "service_name": service.get("name", ""),
                    "inventory_type": kind,
                    "workspace_id": "",
                    "name": summary,
                    "display_name": "",
                    "state": "",
                    "details": "",
                })
            for entry in entries:
                if kind == "API":
                    state = entry.get("api_type", "")
                    details = "; ".join(filter(None, [
                        "path=" + entry.get("path", ""),
                        "revision=" + entry.get("api_revision", ""),
                        "version=" + entry.get("api_version", ""),
                        "subscription required=" + str(entry.get("subscription_required", "")),
                    ]))
                elif kind == "Product":
                    state = entry.get("state", "")
                    details = "; ".join(filter(None, [
                        "approval required=" + str(entry.get("approval_required", "")),
                        "subscription required=" + str(entry.get("subscription_required", "")),
                        "API IDs=" + ", ".join(entry.get("api_ids", [])),
                    ]))
                else:
                    state = entry.get("state", "")
                    details = "; ".join(filter(None, [
                        "owner ID=" + entry.get("owner_id", ""),
                        "scope=" + entry.get("scope", ""),
                    ]))
                apim_inventory.append({
                    "subscription_name": service.get("subscription_name", ""),
                    "resource_group": service.get("resource_group", ""),
                    "service_name": service.get("name", ""),
                    "inventory_type": kind,
                    "workspace_id": entry.get("workspace_id", ""),
                    "name": entry.get("name", ""),
                    "display_name": entry.get("display_name", ""),
                    "state": (state + " (collection partial)"
                              if inventory_status == "partial" else state),
                    "details": details,
                })
    sections.append((
        "APIM APIs, products, and subscriptions", apim_inventory, [
            ("subscription_name", "Subscription"), ("resource_group", "Resource group"),
            ("service_name", "APIM service"), ("inventory_type", "Type"),
            ("workspace_id", "Workspace"), ("name", "Name"),
            ("display_name", "Display name"), ("state", "State / type"),
            ("details", "Configuration"),
        ],
        "Aggregated from the existing APIM service inventory. Subscription keys and API policy XML "
        "are not exported. Service subscriptions are not necessarily equivalent to active consumers.",
    ))

    mapping_rows = []
    for mapping in mappings:
        mapping_rows.append({
            "apim_name": mapping.get("apim_name", ""),
            "backend_name": mapping.get("backend_name", ""),
            "backend_url": mapping.get("backend_url", ""),
            "foundry_resource_name": mapping.get("foundry_resource_name", ""),
            "deployment_name": mapping.get("deployment_name", ""),
            "match_status": mapping.get("match_status", ""),
            "match_basis": mapping.get("match_basis", ""),
        })
    sections.append((
        "APIM backend routing evidence", mapping_rows, [
            ("apim_name", "APIM service"), ("backend_name", "Backend"),
            ("backend_url", "Sanitized backend URL"),
            ("foundry_resource_name", "Matched AI resource"),
            ("deployment_name", "Deployment"), ("match_status", "Match status"),
            ("match_basis", "Evidence"),
        ],
        "Management-plane backend evidence only. A mapping does not prove runtime routing, and "
        "an absent match does not prove an agent or model is unreachable through APIM.",
    ))
    sections.append((
        "Foundry agent definitions and tool connections", [{
            "collection_status": "Not collected by this scanner",
        }], [("collection_status", "Collection status")],
        "The current scan does not enumerate Foundry agent definitions, connected tools, or "
        "multi-agent relationships. This assessment pillar needs additional agent API/SDK coverage.",
    ))

    quota_rows = []
    for quota in tables.get("regional_quotas", []):
        quota_rows.append({
            "subscription_name": quota.get("subscription_name", ""),
            "location": quota.get("location", ""),
            "display_name": quota.get("display_name", ""),
            "usage_name": quota.get("usage_name", ""),
            "current_value": quota.get("current_value", ""),
            "limit": quota.get("limit", ""),
            "unit": quota.get("unit", ""),
        })
    sections.append((
        "Regional AI quota usage", quota_rows, [
            ("subscription_name", "Subscription"), ("location", "Region"),
            ("display_name", "Quota"), ("usage_name", "Usage identifier"),
            ("current_value", "Current value"), ("limit", "Limit"), ("unit", "Azure unit"),
        ],
        "Azure-reported quota usage and native units. Quotas may be shared across resources and are not "
        "per-deployment entitlements.",
    ))
    return sections


def render_report(tables):
    sections = build_sections(tables)
    summary = tables["summary"]
    unknown = [
        ("Foundry public access", sum(not row.get("public_network_access") or
                                     row["public_network_access"].lower() not in ("enabled", "disabled")
                                     for row in tables["foundry_resources"])),
        ("Foundry key access", sum(row.get("key_based_access", "").lower() not in ("allowed", "disabled")
                                  for row in tables["foundry_resources"])),
        ("APIM public access", sum(row.get("public_network_access", "").lower() not in ("enabled", "disabled")
                                  for row in tables["apim_resources"])),
    ]
    html = ["""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Azure AI governance report</title>
<style>
:root{font-family:system-ui,sans-serif;color:#182637;background:#f3f6fa}
body{max-width:1600px;margin:auto;padding:24px}h1{margin-bottom:8px}
header,section{background:white;border:1px solid #d9e2ed;border-radius:10px;padding:20px;margin-bottom:20px}
.pillar{border-left:5px solid #527da8}.pillar>h2{margin-top:0}.report-section{margin:22px 0 0;padding-top:16px;border-top:1px solid #d9e2ed}
.report-section h3{margin:0 0 8px}
.meta,.note{color:#42566d;line-height:1.5}.warning{background:#fff4d6;padding:12px;border-left:4px solid #b36b00}
nav a{display:inline-block;margin:6px 16px 6px 0;color:#075ea8}
.toc{list-style:none;padding-left:0}.toc>li{margin-bottom:12px}.toc ul{padding-left:24px}
.back-to-top{font-size:.9em;margin:8px 0}.back-to-top a{color:#075ea8}
.count{font-size:.8em;background:#e6eef8;padding:3px 9px;border-radius:14px}
.table-wrap{overflow:auto;max-height:650px}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px;border-bottom:1px solid #d9e2ed;vertical-align:top}
th{position:sticky;top:0;background:#edf3fa}td{white-space:pre-line;overflow-wrap:anywhere}
tr:nth-child(even){background:#f8fafc}.empty{padding:12px;background:#edf6ef}
@media print{body{padding:0;background:white}.table-wrap{max-height:none;overflow:visible}th{position:static}section{break-inside:auto}nav,.back-to-top{display:none}}
</style></head><body><header id="top"><h1>Azure AI governance report</h1>"""]
    html.append('<p class="meta">Tenant: ' + escape(str(summary.get("tenant_id", "Unknown"))) +
                "<br>Inventory completed: " + escape(str(summary.get("finished_at", "Unknown"))) +
                "<br>Report generated: " + escape(datetime.now(timezone.utc).isoformat()) +
                "<br>Scope: " + escape(str(summary.get("scope", "Unknown"))) + "</p>")
    html.append('<p class="warning">Scan status: ' + escape(str(summary.get("status", "unknown"))) +
                " · Recorded collection errors: " + str(len(tables["scan_errors"])) +
                ". Findings describe captured configuration, not a live access test.</p>")
    html.append('<p class="note">Unknown or non-binary settings (excluded from enabled lists): ' +
                escape("; ".join(f"{name}: {count}" for name, count in unknown)) +
                ".</p><p class=\"note\">Report sections follow the six assessment pillars in the "
                "Automation Analysis workbook. Only evidence collected by this scan is shown; a missing "
                "section result does not imply a control is absent.</p>"
                '<nav aria-labelledby="toc-heading"><h2 id="toc-heading">Table of contents</h2>'
                '<ul class="toc">')
    grouped = {pillar: [] for pillar in PILLARS}
    for index, section_data in enumerate(sections, 1):
        title, rows, _, _ = section_data
        pillar = SECTION_PILLARS.get(title, PILLARS[-1])
        grouped[pillar].append((index, section_data))
    for pillar_index, pillar in enumerate(PILLARS, 1):
        count = sum(len(rows) for _, (_, rows, _, _) in grouped[pillar])
        html.append(f'<li><a href="#pillar-{pillar_index}">{escape(pillar)} '
                    f'({count} rows)</a>')
        if grouped[pillar]:
            html.append("<ul>")
            for index, (title, rows, _, _) in grouped[pillar]:
                html.append(f'<li><a href="#section-{index}">{escape(title)} '
                            f'({len(rows)})</a></li>')
            html.append("</ul>")
        html.append("</li>")
    html.append("</ul></nav></header>")
    back_to_top = '<p class="back-to-top"><a href="#top">Back to top</a></p>'
    for pillar_index, pillar in enumerate(PILLARS, 1):
        html.append(f'<section class="pillar" id="pillar-{pillar_index}">'
                    f'<h2>{escape(pillar)}</h2>{back_to_top}')
        if not grouped[pillar]:
            html.append('<p class="empty">This scan has no evidence sections for this assessment pillar.</p>')
        for index, (title, rows, columns, note) in grouped[pillar]:
            html.append(f'<div class="report-section" id="section-{index}"><h3>{escape(title)} '
                        f'<span class="count">{len(rows)}</span></h3>'
                        f'{back_to_top}<p class="note">{escape(note)}</p>')
            if not rows:
                html.append('<p class="empty">No matching records in the captured inventory.</p>')
            else:
                html.append('<div class="table-wrap"><table><thead><tr>')
                html.extend("<th scope=\"col\">" + escape(label) + "</th>" for _, label in columns)
                html.append("</tr></thead><tbody>")
                for row in sorted(rows, key=lambda r: (
                        r.get("subscription_name", ""), r.get("resource_group", ""),
                        r.get("name", r.get("resource_name", "")),
                        r.get("principal_id", ""))):
                    html.append("<tr>")
                    html.extend("<td>" + escape(str("" if row.get(key) is None else row.get(key, ""))) +
                                "</td>" for key, _ in columns)
                    html.append("</tr>")
                html.append("</tbody></table></div>")
            html.append(back_to_top + "</div>")
        html.append(back_to_top + "</section>")
    html.append("</body></html>")
    return "\n".join(html)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path, help="Directory from a single scan")
    parser.add_argument("--output", type=Path, help="New HTML file; defaults to input_dir/governance-report.html")
    args = parser.parse_args()
    output = args.output or args.input_dir / "governance-report.html"
    try:
        tables = load_inventory(args.input_dir)
        html = render_report(tables)
        with output.open("x", encoding="utf-8") as handle:
            handle.write(html)
        output.chmod(0o600)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Report failed: {exc}", file=sys.stderr)
        return 1
    for title, rows, _, _ in build_sections(tables):
        print(f"{title}: {len(rows)}")
    print(f"HTML report: {output.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
