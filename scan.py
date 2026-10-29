#!/usr/bin/env python3
"""Scan the current Azure CLI tenant without modifying cloud resources."""

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

from discovery.azure import AzureClient, cli_json


SCHEMAS = {
    "subscriptions": ["subscription_id", "subscription_name", "tenant_id", "state",
                      "scan_status", "policy_assignment_count", "policy_assignments",
                      "policy_assignment_status"],
    "foundry_resources": ["id", "name", "type", "kind", "location", "subscription_id",
                          "subscription_name", "tenant_id", "resource_group", "parent_id",
                          "endpoint", "endpoints", "disable_local_auth", "key_based_access",
                          "key_based_access_source_resource_id", "private_endpoint_count",
                          "private_endpoint_connections", "rai_policies",
                          "rai_policy_inventory_status", "diagnostic_setting_count",
                          "diagnostic_settings", "diagnostic_settings_status"],
    "model_deployments": ["id", "name", "resource_id", "account_id", "subscription_id",
                          "subscription_name", "tenant_id", "resource_group", "location",
                          "model_name", "model_version", "model_format", "deployment_type",
                          "capacity", "capacity_unit", "allocated_tpm", "endpoint",
                          "rai_policy_name"],
    "regional_quotas": ["subscription_id", "subscription_name", "tenant_id", "location",
                        "usage_name", "display_name", "current_value", "limit", "unit"],
    "foundry_role_assignments": ["foundry_resource_id", "foundry_resource_name",
                                "foundry_resource_type", "subscription_id", "subscription_name",
                                "tenant_id", "resource_group", "assignment_id", "assignment_scope",
                                "assignment_relationship", "principal_id", "principal_type",
                                "role_definition_id", "role_name", "role_type", "condition",
                                "condition_version"],
    "model_usage": ["deployment_id", "deployment_name", "resource_id", "subscription_id",
                    "subscription_name", "resource_group", "model_name", "model_version",
                    "window_days", "window_start", "window_end", "total_requests",
                    "successful_requests", "failed_requests", "other_requests", "prompt_tokens",
                    "completion_tokens", "usage_status", "metric_source", "notes"],
    "model_retirements": ["deployment_id", "deployment_name", "resource_id", "subscription_id",
                          "subscription_name", "resource_group", "model_name", "model_version",
                          "lifecycle", "retirement_date", "replacement", "days_to_retirement",
                          "retirement_status", "warning_days", "source_url",
                          "schedule_retrieved_at", "notes"],
    "apim_resources": ["id", "name", "subscription_id", "subscription_name", "tenant_id",
                       "resource_group", "location", "sku", "gateway_url", "api_count",
                       "api_inventory", "product_count", "product_inventory",
                       "subscription_count", "subscription_inventory",
                       "api_inventory_status", "product_inventory_status",
                       "subscription_inventory_status", "diagnostic_setting_count",
                       "diagnostic_settings", "diagnostic_settings_status"],
    "apim_backends": ["id", "name", "apim_id", "apim_name", "workspace_id", "url",
                      "resource_id", "protocol", "backend_type", "pool_members"],
    "apim_foundry_mappings": ["apim_id", "apim_name", "backend_id", "backend_name",
                              "backend_url", "foundry_resource_id", "foundry_resource_name",
                              "deployment_id", "deployment_name", "match_status", "match_basis"],
    "scan_errors": ["scope", "operation", "message"],
}


def csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"))
    text = str(value)
    # Prevent spreadsheet formula execution when opening tenant-controlled names.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def write_csv(path, rows, columns):
    extra = sorted({key for row in rows for key in row} - set(columns))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns + extra)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(value) for key, value in row.items()})


def run(output, retirement_warning_days=90):
    from discovery.apim import collect_apim, map_backends
    from discovery.foundry import collect_foundry, collect_quotas
    from discovery.rbac import collect_role_assignments
    from discovery.usage import collect_usage
    from discovery.retirements import collect_retirements
    from discovery.policy import collect_policy_assignments
    from discovery.monitoring import attach_diagnostic_settings

    os.umask(0o077)
    started = datetime.now(timezone.utc).isoformat()
    account = cli_json(["account", "show"])
    tenant = account["tenantId"]
    endpoint = cli_json(["cloud", "show"])["endpoints"]["resourceManager"]
    client = AzureClient(endpoint)
    # Query ARM in the current tenant instead of refreshing unrelated cached tenants.
    visible = client.list("/subscriptions", "2022-12-01")
    if client.errors:
        raise RuntimeError("Could not enumerate subscriptions completely; see warnings above")
    subscriptions = [
        {"id": s["subscriptionId"], "name": s["displayName"],
         "tenantId": s.get("tenantId", tenant), "state": s.get("state", "")}
        for s in visible if s.get("tenantId", tenant).lower() == tenant.lower()
    ]
    if not subscriptions:
        raise RuntimeError("No accessible subscriptions found in the current tenant")
    output.mkdir(parents=True, exist_ok=False)
    tables = {name: [] for name in SCHEMAS}
    role_definitions = {}
    for subscription in subscriptions:
        subrow = {
            "subscription_id": subscription["id"], "subscription_name": subscription["name"],
            "tenant_id": tenant, "state": subscription.get("state", ""),
        }
        tables["subscriptions"].append(subrow)
        if subscription.get("state", "").lower() != "enabled":
            subrow["scan_status"] = "skipped_non_enabled"
            client.error(subscription["id"], "subscription", "Subscription is not Enabled; not scanned")
            continue
        print(f"Scanning {subscription['name']} ({subscription['id']})", flush=True)
        failures = len(client.errors)
        previous_errors = len(client.errors)
        assignments = collect_policy_assignments(client, subscription)
        subrow["policy_assignment_count"] = len(assignments)
        subrow["policy_assignments"] = json.dumps(assignments, sort_keys=True)
        subrow["policy_assignment_status"] = (
            "partial" if len(client.errors) > previous_errors else "complete"
        )
        resources, deployments = collect_foundry(client, subscription)
        quotas = collect_quotas(client, subscription, resources)
        assignments = collect_role_assignments(client, resources, role_definitions)
        services, backends = collect_apim(client, subscription)
        attach_diagnostic_settings(client, resources)
        attach_diagnostic_settings(client, services)
        tables["foundry_resources"].extend(resources)
        tables["model_deployments"].extend(deployments)
        tables["regional_quotas"].extend(quotas)
        tables["foundry_role_assignments"].extend(assignments)
        tables["apim_resources"].extend(services)
        tables["apim_backends"].extend(backends)
        subrow["scan_status"] = "partial" if len(client.errors) > failures else "complete"
        # Persist completed subscription work even if a later scan is interrupted.
        tables["scan_errors"] = client.errors
        for name, rows in tables.items():
            write_csv(output / (name + ".csv"), rows, SCHEMAS[name])
    observed_at = datetime.now(timezone.utc)
    enrichment_errors = len(client.errors)
    tables["model_usage"] = collect_usage(client, tables["model_deployments"], now=observed_at)
    tables["model_retirements"] = collect_retirements(
        client, tables["model_deployments"], now=observed_at, warning_days=retirement_warning_days
    )
    # Enrichment failures also affect completeness, even when resource listing succeeded.
    for subrow in tables["subscriptions"]:
        if subrow.get("scan_status") == "complete":
            for error in client.errors[enrichment_errors:]:
                if (subrow["subscription_id"].lower() in error["scope"].lower()
                        or error["scope"].startswith("https://learn.microsoft.com/")):
                    subrow["scan_status"] = "partial"
                    break
    tables["apim_foundry_mappings"] = map_backends(
        tables["apim_backends"], tables["foundry_resources"], tables["model_deployments"]
    )
    tables["scan_errors"] = client.errors
    for name, rows in tables.items():
        write_csv(output / (name + ".csv"), rows, SCHEMAS[name])
    summary = {
        "tenant_id": tenant, "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "partial" if client.errors else "complete",
        "counts": {name: len(rows) for name, rows in tables.items()},
        "successful_requests": sum(r["status"] == "ok" for r in client.requests),
        "usage_windows_days": [7, 30],
        "inactivity_rule": "Zero successful requests; failed attempts reported separately",
        "retirement_warning_days": retirement_warning_days,
        "scope": "Subscriptions visible to the signed-in principal in the current Azure CLI tenant",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"CSV output: {output.resolve()}")
    return 2 if client.errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("outputs") /
                        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
                        help="New directory for CSV files; existing directories are never overwritten")
    parser.add_argument("--retirement-warning-days", type=int, default=90,
                        help="Flag model retirement dates within this many days (default: 90)")
    args = parser.parse_args()
    if args.retirement_warning_days < 0:
        parser.error("--retirement-warning-days must be non-negative")
    try:
        return run(args.output_dir, retirement_warning_days=args.retirement_warning_days)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
