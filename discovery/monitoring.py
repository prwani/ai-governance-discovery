"""Read-only diagnostic-setting coverage for discovered Azure resources."""

import json


API_VERSION = "2021-05-01-preview"


def diagnostic_summary(setting):
    properties = setting.get("properties", {})
    logs = properties.get("logs", [])
    metrics = properties.get("metrics", [])
    return {
        "id": setting.get("id", ""),
        "name": setting.get("name", ""),
        "workspace_id": properties.get("workspaceId", ""),
        "storage_account_id": properties.get("storageAccountId", ""),
        "event_hub_authorization_rule_id": properties.get(
            "eventHubAuthorizationRuleId", ""),
        "event_hub_name": properties.get("eventHubName", ""),
        "log_analytics_destination_type": properties.get(
            "logAnalyticsDestinationType", ""),
        "destination_types": [
            name for name, value in (
                ("workspace", properties.get("workspaceId")),
                ("storage_account", properties.get("storageAccountId")),
                ("event_hub", properties.get("eventHubAuthorizationRuleId")),
            ) if value
        ],
        "enabled_log_categories": sorted({
            item.get("category") or item.get("categoryGroup", "")
            for item in logs if isinstance(item, dict) and item.get("enabled") is True
        } - {""}),
        "enabled_metric_categories": sorted({
            item.get("category", "")
            for item in metrics if isinstance(item, dict) and item.get("enabled") is True
        } - {""}),
    }


def attach_diagnostic_settings(client, resources):
    for resource in resources:
        path = (resource["id"].rstrip("/") +
                "/providers/Microsoft.Insights/diagnosticSettings")
        previous_errors = len(getattr(client, "errors", ()))
        settings = [
            diagnostic_summary(setting)
            for setting in client.list(path, API_VERSION)
        ]
        resource["diagnostic_setting_count"] = len(settings)
        resource["diagnostic_settings"] = json.dumps(settings, sort_keys=True)
        resource["diagnostic_settings_status"] = (
            "partial" if len(getattr(client, "errors", ())) > previous_errors else "complete"
        )
