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
.meta,.note{color:#42566d;line-height:1.5}.warning{background:#fff4d6;padding:12px;border-left:4px solid #b36b00}
nav a{display:inline-block;margin:6px 16px 6px 0;color:#075ea8}
.count{font-size:.8em;background:#e6eef8;padding:3px 9px;border-radius:14px}
.table-wrap{overflow:auto;max-height:650px}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px;border-bottom:1px solid #d9e2ed;vertical-align:top}
th{position:sticky;top:0;background:#edf3fa}td{white-space:pre-line;overflow-wrap:anywhere}
tr:nth-child(even){background:#f8fafc}.empty{padding:12px;background:#edf6ef}
@media print{body{padding:0;background:white}.table-wrap{max-height:none;overflow:visible}th{position:static}section{break-inside:auto}nav{display:none}}
</style></head><body><header><h1>Azure AI governance report</h1>"""]
    html.append('<p class="meta">Tenant: ' + escape(str(summary.get("tenant_id", "Unknown"))) +
                "<br>Inventory completed: " + escape(str(summary.get("finished_at", "Unknown"))) +
                "<br>Report generated: " + escape(datetime.now(timezone.utc).isoformat()) +
                "<br>Scope: " + escape(str(summary.get("scope", "Unknown"))) + "</p>")
    html.append('<p class="warning">Scan status: ' + escape(str(summary.get("status", "unknown"))) +
                " · Recorded collection errors: " + str(len(tables["scan_errors"])) +
                ". Findings describe captured configuration, not a live access test.</p>")
    html.append('<p class="note">Unknown or non-binary settings (excluded from enabled lists): ' +
                escape("; ".join(f"{name}: {count}" for name, count in unknown)) +
                ".</p><nav>")
    for index, (title, rows, _, _) in enumerate(sections, 1):
        html.append(f'<a href="#section-{index}">{index}. {escape(title)} ({len(rows)})</a>')
    html.append("</nav></header>")
    for index, (title, rows, columns, note) in enumerate(sections, 1):
        html.append(f'<section id="section-{index}"><h2>{index}. {escape(title)} '
                    f'<span class="count">{len(rows)}</span></h2><p class="note">{escape(note)}</p>')
        if not rows:
            html.append('<p class="empty">No matching records in the captured inventory.</p>')
        else:
            html.append('<div class="table-wrap"><table><thead><tr>')
            html.extend("<th scope=\"col\">" + escape(label) + "</th>" for _, label in columns)
            html.append("</tr></thead><tbody>")
            for row in sorted(rows, key=lambda r: (
                    r.get("subscription_name", ""), r.get("resource_group", ""),
                    r.get("name", ""), r.get("principal_id", ""))):
                html.append("<tr>")
                html.extend("<td>" + escape(str("" if row.get(key) is None else row.get(key, ""))) +
                            "</td>" for key, _ in columns)
                html.append("</tr>")
            html.append("</tbody></table></div>")
        html.append("</section>")
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
