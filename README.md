# Azure AI governance discovery

Read-only Python 3.10+ scripts using the existing Azure CLI login. No Python
packages, Azure CLI extensions, model inference calls, or cloud changes required.

```bash
az login --use-device-code
python3 scan.py
# Optional: choose a NEW output directory
python3 scan.py --output-dir outputs/my-scan
python3 -m unittest discover -s tests -v
```

## Prerequisites and permissions

- **`scan.py`**: Python 3.10+ and Azure CLI, signed in to the target tenant with
  `az login`. Assign the built-in **Reader** role on every subscription to scan.
  For a custom role, grant the required read actions, including
  `Microsoft.Insights/metricDefinitions/read`,
  `Microsoft.Insights/metrics/read`,
  `Microsoft.Authorization/roleAssignments/read`, and
  `Microsoft.Authorization/roleDefinitions/read`. Tenant-wide results require
  access to every enabled subscription; inaccessible subscriptions are not scanned.
- **`report.py`**: Python 3.10+ and a completed scan output directory. It runs
  offline and requires no Azure login or Azure role.

## Prompt to regenerate this project

Use this prompt in a new GitHub Copilot session with the working directory set
to a completely empty folder on a separate machine and in a different
organization. It must not depend on this repository or its files:

```text
Create from scratch in the current empty directory a complete, read-only Azure
AI governance discovery tool; do not assume any source repository, existing
files, prior conversation, organization-specific configuration, or credentials.
First outline the files you will create, then implement the working project:
Python 3.10+ scanner, modular discovery code, offline HTML report generator,
focused unit tests, and a README with setup, permissions, usage, output schemas,
limitations, and regeneration instructions. Avoid runtime Python dependencies.

Authenticate through Azure CLI (`az login --use-device-code`) and use the
signed-in tenant's ARM endpoint and GET requests only. Never change cloud
resources, invoke models, retrieve or export secrets, or send inventory data
outside the machine. Scan all enabled subscriptions visible to the signed-in
principal in the current tenant, not just the selected subscription. Clearly
identify inaccessible subscriptions, failed collection, and partial results;
never represent a failed query as an empty result.

Write each scan into a new local output directory and export CSVs plus a JSON
summary. Include these inventories and attributes (leave unavailable values
blank/unknown; do not infer them):

- Subscriptions: ID, name, tenant, state, and scan status.
- Azure AI/Foundry accounts, native projects, ML workspaces and legacy hubs:
  ARM ID, name, resource type/kind, location, subscription/resource group,
  parent/hub ID, provisioning state, endpoint(s), public network access, and
  local/key authentication status. For projects, identify the parent account
  as the source of inherited authentication configuration.
- Model deployments: deployment/resource/account IDs, name, model name/version/
  format/publisher, deployment SKU/type, capacity and unit (distinguish PTU
  from other capacity), allocated TPM only when supported by explicit token
  rate-limit data, endpoint, provisioning state, upgrade option, and applicable
  ML endpoint name/ID and traffic weights.
- Regional quotas: subscription, region, usage name/display name, current
  allocation, limit, and Azure's native unit.
- Foundry RBAC assignments: resource, assignment ID/scope and direct/inherited
  relationship, principal ID/type, role definition/name/type, and conditions.
  Do not claim this is a complete effective-access calculation.
- Model usage: deployment and model identity, separate 7- and 30-day windows,
  timestamps, total/successful/failed/other requests, prompt/completion tokens,
  metric source, collection status, and explanatory notes. Missing or
  unsupported telemetry is unknown, not zero.
- Model retirements: exact model/version, lifecycle, published date, replacement,
  days to retirement, status, warning window, source URL/retrieval time, and
  notes. Retrieve only factual schedule metadata from a fixed public Microsoft
  source; never send inventory data to it.
- API Management services: resource identity, location, SKU/capacity, gateway,
  provisioning/network status; backends: service/workspace, URL, ARM reference,
  protocol/type, and pool members; mappings: backend/resource/deployment
  identities, match status, and evidence. Distinguish confirmed deployment
  matches from resource-only, endpoint-only, ambiguous, unresolved, and unmatched
  evidence; do not claim inventory proves runtime routing.
- Errors and summary: failed operation/scope/message, tenant, start/end times,
  row counts, completeness, and metric/retirement collection context.

Include safe pagination and bounded retries, restrict ARM requests to the
configured endpoint, filter sensitive URL data, escape spreadsheet
formula-like CSV values, and protect output files. Generate a standalone,
escaped HTML governance report from a scan directory without network access or
Azure login. It should highlight Foundry/APIM public access, key-based access,
user/service-principal role assignments, deployments without confirmed APIM
mappings, zero successful requests (with failures and unknown telemetry
separate), and past/upcoming retirements (with unresolved matches separate).

Document that tenant-wide visibility requires Reader access on each subscription.
List the additional read permissions needed for metrics
(`Microsoft.Insights/metricDefinitions/read` and
`Microsoft.Insights/metrics/read`) and role assignments/definitions
(`Microsoft.Authorization/roleAssignments/read` and
`Microsoft.Authorization/roleDefinitions/read`). Make collection failures
visible when these permissions are missing. Add focused tests for scanner,
discovery, safety, and report behavior. Run the tests and report what was
created, the test results, and any remaining limitations; do not claim Azure
access or live cloud validation unless actually performed.
```

## HTML governance report

Generate a standalone, offline HTML report from any single scan directory:

```bash
python3 scan.py --output-dir outputs/my-scan
python3 report.py outputs/my-scan
# Optional custom destination (must not already exist):
python3 report.py outputs/my-scan --output governance-report.html
```

The default file is `outputs/my-scan/governance-report.html`. Open it in a browser;
no web server, external assets, JavaScript, packages or Azure login are needed for
report generation. Inventory values are HTML-escaped. Existing reports are never
overwritten. The report contains:

1. Foundry resources with explicit public network access enabled.
2. Foundry resources with key-based access allowed.
3. APIM resources with explicit public network access enabled.
4. Foundry User/ServicePrincipal role assignments, grouped by resource/principal,
   with all assigned roles, scopes and conditions. This is not an effective
   permission calculation; unrelated-service RBAC roles do not prove Foundry access.
5. Model deployments without a confirmed deployment-level APIM backend mapping,
   separating account/endpoint-level matches from absent matches.
6. Deployments with zero successful requests over 7 and 30 days, with failed
   attempts displayed separately and unknown telemetry clearly separated.
7. Deployments past their published retirement date or retiring within 90 days,
   with dates, replacement suggestions and unresolved matches.

The first two sections show only subscription, resource group and resource name.
Unknown access settings are counted separately, not assumed enabled or disabled.
Public networking configuration does not guarantee internet reachability.
Old scans without APIM's `public_network_access` column report that setting as
unknown; run a new scan to populate it. Missing mapping evidence cannot prove
that a deployment is not routed through APIM policies or runtime selection.
Collection errors and scan status are prominently displayed.

The scanner lists subscriptions directly from ARM and scans **every enabled subscription
visible to the signed-in principal in the current Azure CLI tenant**, not just the
selected subscription. It does not change the selected subscription. Tenant-wide
visibility requires Reader access to every subscription, typically inherited from
the tenant root management group. Subscriptions inaccessible to the principal
cannot be enumerated; disabled subscriptions are reported as skipped.

## Output

Each run creates a new private directory under `outputs/`:

| File | Contents |
|---|---|
| `subscriptions.csv` | Subscription scope and complete/partial/skipped status |
| `foundry_resources.csv` | AI Services/Foundry and OpenAI accounts, native projects, ML workspaces including legacy hubs/projects |
| `model_deployments.csv` | Account model deployments and workspace online/batch deployments and serverless endpoints |
| `regional_quotas.csv` | Subscription/region quota usage names, current allocation, limits and native units |
| `foundry_role_assignments.csv` | Direct and inherited Azure RBAC assignments for each discovered Foundry resource/project |
| `model_usage.csv` | Deployment request/token metrics for separate 7- and 30-day windows, including collection status |
| `model_retirements.csv` | Exact model/version retirement comparisons, source timestamps and 90-day warnings |
| `apim_resources.csv` | All API Management services |
| `apim_backends.csv` | Service and workspace backend URLs, ARM references and backend pool members |
| `apim_foundry_mappings.csv` | Backend-to-resource/deployment relationships with evidence and match status |
| `scan_errors.csv` | Failed requests, missing access, invalid responses and skipped subscriptions |
| `summary.json` | Tenant, timestamps, row counts and overall completeness |

Regional quotas are exported separately, including quotas without a matching
deployment, for regions containing discovered Cognitive Services accounts.

All lists are paginated. Transient throttling/server errors and timeouts are
retried with bounded backoff. Completed subscription inventories are checkpointed.
Exit codes: **0** complete within visible subscription scope; **2** partial
inventory (inspect errors); **1** startup or fatal failure. A failed list must not
be interpreted as an empty subscription. Files remain local; `outputs/` is ignored
by Git. Treat inventories as confidential infrastructure metadata.

`foundry_resources.csv` includes `key_based_access` (`allowed`, `disabled`, or
`unknown`) and the raw boolean `disable_local_auth`. Azure's `disableLocalAuth=true`
disables key-based authentication; `false` allows it. Missing or non-boolean
values remain unknown rather than assumed allowed. Native Foundry projects
report their parent account's authentication setting, identified by
`key_based_access_source_resource_id`. This is an authentication configuration,
not a connectivity check: firewall/network rules may still block access.
No keys are retrieved.

## Model usage and retirement

The scanner queries Azure Monitor for deployment-level request and token metrics
where supported, using the same UTC end time for both lookback windows. Reader
permissions must include `Microsoft.Insights/metricDefinitions/read` and
`Microsoft.Insights/metrics/read`. The rule is **zero successful requests**, not
zero attempts: failed requests appear separately. A deployment receiving only
failed requests needs investigation, not automatic removal.

Missing/null telemetry and unsupported model metrics are not converted to zero.
Image, audio, non-OpenAI and managed ML deployments may not expose the same metrics.
New or recreated deployment names may not have a full window of attributable
history; this report is a cleanup lead, not authorization to delete models.
Metrics do not contain prompts/responses and do not require enabling diagnostic logs.

The retirement collector fetches Microsoft's public
[retirement schedule](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/model-retirement-schedule)
and stores only matching factual lifecycle/date metadata. No inventory is sent
to that website. It matches exact model names and versions, flags published past
dates and upcoming dates, and preserves missing/ambiguous matches rather than
guessing. Dates and replacement recommendations can change; retrieval timestamps
are recorded. Fine-tuned and publisher-specific schedules must not be treated as
base-model inference schedules.

```bash
python3 scan.py --output-dir outputs/new-scan --retirement-warning-days 90
python3 report.py outputs/new-scan
```

Report generation is still offline; older scans without these CSVs show that
usage/retirement collection was not included, not that all deployments are healthy.

## Role assignments

`foundry_role_assignments.csv` has one row per Foundry resource + applicable
assignment, including assignments inherited from account, resource group,
subscription or management group scopes. The same inherited assignment therefore
appears for each resource it applies to. Includes all role types, not just
Foundry-specific roles. Role definition lookups provide readable role names;
principal IDs/types are retained without Microsoft Graph queries for names or
group membership expansion. Conditions are preserved, not evaluated.

Requires `Microsoft.Authorization/roleAssignments/read` on scanned scopes and
`Microsoft.Authorization/roleDefinitions/read` for role names. Failures appear in
`scan_errors.csv`; a failed lookup must not be interpreted as no assignments.
This is an Azure RBAC assignment inventory, not a complete effective-access
calculation: deny assignments, unactivated PIM eligibility, directory roles and
data-plane ACLs are not included. Activated PIM grants appear when returned by
the role assignments API. Subresource-only assignments below a scanned resource
are not attributed to its parent; native projects are scanned as their own scopes.

## TPM, quotas and deployment types

`deployment_type` retains the exact SKU returned by Azure, e.g. `Standard`,
`GlobalStandard`, `DataZoneStandard`, `ProvisionedManaged`, `GlobalProvisionedManaged`,
or `DataZoneProvisionedManaged`. Provisioned capacity is PTU, **not TPM**.

`capacity` preserves SKU capacity; it is **not universally capacity x 1,000 TPM**.
`allocated_tpm` is calculated from explicit token rate-limit rules:
`count * 60 / renewalPeriod`, taking the tightest returned token limit. If a
Standard deployment omits those rules, exact matching model/SKU token rates per
capacity unit are multiplied by its capacity. The source is recorded in `tpm_source`.
Request-rate rules are not treated as token limits. Missing limits remain blank.
Dynamic throttling and actual throughput can differ from configured limits.

`model_deployments.csv` contains deployment allocation and configuration, not
regional quota attributes. `regional_quotas.csv` retains Azure's `usage_name`,
`current_value`, `limit` and `unit` without assuming `Count` means TPM.
Quota limits are shared across resources in the subscription/region/model/SKU
pool, not independent per-deployment entitlements.

## Mapping interpretation and limits

`deployment_confirmed` requires an explicit deployment name in a backend URL/ARM
reference or a unique serverless scoring endpoint match. `resource_only` means
the backend identifies an account but not a deployment: the scanner deliberately
does **not** manufacture a mapping to every model in the account. ML online/batch
endpoint routing is `endpoint_only` because traffic weights, runtime headers and
policies may choose a deployment. Backend pools are expanded with member evidence;
unmatched, ambiguous, unresolved named-value and cyclic pool references remain
visible in the CSV.

This is a **management-plane backend inventory**, not proof of runtime API
routing. Inline `set-backend-service` policies, API `serviceUrl`, policy
expressions, request-body model selection, DNS/CNAME aliases, external gateways,
data-plane project-only connections and Foundry projects in inaccessible
subscriptions are not resolved. Named values are not expanded. Credentials,
backend authorization/headers, subscription keys, scoring keys and raw backend
property objects are never exported. URL userinfo, fragments and query parameters
other than deployment identifiers and API version are removed. Spreadsheet
formula-like CSV cells are escaped.

## References

- [Microsoft Foundry skill](https://github.com/microsoft/azure-skills/tree/main/skills/microsoft-foundry)
- [Foundry quota guidance](https://github.com/microsoft/azure-skills/blob/main/skills/microsoft-foundry/quota/quota.md)
- [Deployment REST API](https://learn.microsoft.com/rest/api/aiservices/accountmanagement/deployments/list)
- [Model metadata REST API](https://learn.microsoft.com/rest/api/aiservices/accountmanagement/accounts/list-models)
- [APIM backend REST API](https://learn.microsoft.com/rest/api/apimanagement/backend/list-by-service)
