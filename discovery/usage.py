"""Read-only Azure Monitor usage metrics for model deployments."""

from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode


MONITOR_VERSION = "2023-10-01"
METRIC_DEFINITIONS_VERSION = "2018-01-01"
METRIC_NAMESPACE = "Microsoft.CognitiveServices/accounts"
WINDOWS = (7, 30)
REQUEST_METRIC = "AzureOpenAIRequests"
PROMPT_METRIC = "ProcessedPromptTokens"
COMPLETION_METRIC = "GeneratedTokens"


def _utc(value):
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value):
    return value.isoformat().replace("+00:00", "Z")


def _metric_name(metric):
    name = metric.get("name", "")
    return name.get("value", "") if isinstance(name, dict) else str(name)


def _dimension_names(definition):
    return {
        str(dimension.get("value", dimension.get("name", ""))).casefold()
        for dimension in definition.get("dimensions", [])
        if isinstance(dimension, dict)
    }


def _supports_total(definition):
    aggregations = definition.get("supportedAggregationTypes", [])
    primary = definition.get("primaryAggregationType", "")
    values = [str(value).casefold() for value in aggregations]
    values.append(str(primary).casefold())
    return any(value in ("total", "sum") for value in values)


def _definitions(client, resource_id):
    path = resource_id.rstrip("/") + "/providers/Microsoft.Insights/metricDefinitions"
    response = client.get(path, METRIC_DEFINITIONS_VERSION)
    if response is None:
        return None
    values = response.get("value")
    if not isinstance(values, list):
        client.error(path, "metricDefinitions", "Missing metric definition value array")
        return None
    return _index_metrics(values)


def _index_metrics(values):
    indexed = {}
    for item in values:
        if not isinstance(item, dict) or not _metric_name(item):
            continue
        name = _metric_name(item).casefold()
        if name not in indexed:
            indexed[name] = item
            continue
        existing = indexed[name]
        series = item.get("timeseries", item.get("timeSeries", []))
        if isinstance(series, list):
            existing.setdefault("timeseries", []).extend(series)
        if item.get("error"):
            existing["error"] = item["error"]
        if _metric_failed(item):
            existing["errorCode"] = item.get("errorCode", "MetricError")
    return indexed


def _metric_failed(metric):
    return bool(metric.get("error")) or str(metric.get("errorCode", "")).casefold() not in (
        "", "success", "0",
    )


def _supported(definitions, metric_name, required_dimensions):
    definition = definitions.get(metric_name.casefold())
    if not definition or not _supports_total(definition):
        return False
    return required_dimensions.issubset(_dimension_names(definition))


def _metric_query(client, resource_id, metric_names, start, end, has_status):
    filters = ["ModelDeploymentName eq '*'"]
    if has_status:
        filters.append("StatusCode eq '*'")
    query = urlencode({
        "timespan": _iso(start) + "/" + _iso(end),
        "interval": "PT1H",
        "metricnames": ",".join(metric_names),
        "aggregation": "Total",
        "top": "1000",
        "$filter": " and ".join(filters),
        "metricnamespace": METRIC_NAMESPACE,
    })
    path = resource_id.rstrip("/") + "/providers/Microsoft.Insights/metrics?" + query
    response = client.get(path, MONITOR_VERSION)
    if response is None:
        return None
    values = response.get("value")
    if not isinstance(values, list):
        client.error(path, "metrics", "Missing metric value array")
        return None
    indexed = _index_metrics(values)
    for metric_name in metric_names:
        item = indexed.get(metric_name.casefold())
        if item is None:
            client.error(path, "metrics", f"Requested metric {metric_name} missing from response")
        elif _metric_failed(item):
            client.error(path, "metrics", f"Requested metric {metric_name} returned a metric error")
    for item in indexed.values():
        series = item.get("timeseries", item.get("timeSeries", []))
        item["_potentially_truncated"] = isinstance(series, list) and len(series) >= 1000
    return indexed


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value) if int(value) == value else value


def _series_for_deployment(metric, deployment_name):
    series_list = metric.get("timeseries", metric.get("timeSeries", []))
    if not isinstance(series_list, list):
        return None
    matching = []
    for series in series_list:
        if not isinstance(series, dict):
            continue
        dimensions = {}
        metadata = series.get("metadatavalues", series.get("metadataValues", []))
        for item in metadata if isinstance(metadata, list) else []:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            if isinstance(name, dict):
                name = name.get("value", "")
            dimensions[str(name).casefold()] = str(item.get("value", ""))
        if dimensions.get("modeldeploymentname", "").casefold() == deployment_name.casefold():
            matching.append((dimensions, series))
    return matching


def _series_total(series):
    points = series.get("data")
    if not isinstance(points, list) or not points:
        return None
    total = 0
    seen = False
    for point in points:
        if not isinstance(point, dict):
            continue
        value = point.get("total", point.get("Total"))
        if value is None:
            continue
        number = _number(value)
        if number is None:
            continue
        total += number
        seen = True
    return _number(total) if seen else None


def _request_counts(metric, deployment_name):
    if not isinstance(metric, dict) or _metric_failed(metric):
        return None
    if metric.get("_potentially_truncated"):
        return {
            "total": None, "successful": None, "failed": None, "other": None,
            "unknown_status": True, "truncated": True,
        }
    matching = _series_for_deployment(metric, deployment_name)
    if not matching:
        return None

    counts = {"successful": 0, "failed": 0, "other": 0}
    total = 0
    has_status = False
    has_success = False
    unknown_status = False
    for dimensions, series in matching:
        if "statuscode" not in dimensions:
            unknown_status = True
            continue
        amount = _series_total(series)
        if amount is None:
            unknown_status = True
            continue
        has_status = True
        total += amount
        status = "".join(character for character in dimensions["statuscode"].casefold()
                         if character.isalnum())
        http_code = int(status) if len(status) == 3 and status.isascii() and status.isdigit() else None
        if status in ("successful", "success") or (http_code is not None and 200 <= http_code < 300):
            has_success = True
            counts["successful"] += amount
        elif status in ("clienterrors", "servererrors", "failed", "failure") \
                or (http_code is not None and 400 <= http_code < 600):
            counts["failed"] += amount
        else:
            counts["other"] += amount
            unknown_status = True
    if not has_status:
        return None
    counts["total"] = _number(total)
    counts["successful"] = _number(counts["successful"])
    counts["failed"] = _number(counts["failed"])
    counts["other"] = _number(counts["other"])
    counts["unknown_status"] = unknown_status or not has_success
    return counts


def _token_total(metric, deployment_name):
    if not isinstance(metric, dict) or _metric_failed(metric):
        return None
    if metric.get("_potentially_truncated"):
        return None
    matching = _series_for_deployment(metric, deployment_name)
    if not matching:
        return None
    total = 0
    seen = False
    for _, series in matching:
        amount = _series_total(series)
        if amount is not None:
            total += amount
            seen = True
    return _number(total) if seen else None


def _is_cognitive_account(resource_id):
    return "/providers/microsoft.cognitiveservices/accounts/" in resource_id.casefold()


def _base_row(deployment, days, start, end):
    deployment_id = deployment.get("id", "")
    return {
        "deployment_id": deployment_id,
        "deployment_name": deployment.get("name", ""),
        "resource_id": deployment.get("resource_id", deployment.get("account_id", "")),
        "subscription_id": deployment.get("subscription_id", ""),
        "subscription_name": deployment.get("subscription_name", ""),
        "resource_group": deployment.get("resource_group", ""),
        "model_name": deployment.get("model_name", ""),
        "model_version": deployment.get("model_version", ""),
        "window_days": days,
        "window_start": _iso(start),
        "window_end": _iso(end),
        "total_requests": None,
        "successful_requests": None,
        "failed_requests": None,
        "other_requests": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "usage_status": "unknown",
        "metric_source": "",
        "notes": "",
    }


def collect_usage(client, deployments, now=None):
    """Return one usage row per deployment and window, retaining unknown telemetry as unknown."""
    end = _utc(now)
    rows = []
    accounts = {}
    query_cache = {}

    def query(resource_id, days, metric_names, has_status):
        key = (resource_id.rstrip("/").casefold(), days, tuple(metric_names), has_status)
        if key not in query_cache:
            query_cache[key] = _metric_query(
                client, resource_id, metric_names, end - timedelta(days=days), end, has_status
            )
        return query_cache[key]

    for deployment in deployments:
        resource_id = deployment.get("resource_id", deployment.get("account_id", ""))
        account_key = resource_id.rstrip("/").casefold()
        if _is_cognitive_account(resource_id) and account_key not in accounts:
            accounts[account_key] = _definitions(client, resource_id)

    for deployment in deployments:
        resource_id = deployment.get("resource_id", deployment.get("account_id", ""))
        is_supported_resource = _is_cognitive_account(resource_id)
        definitions = accounts.get(resource_id.rstrip("/").casefold())
        request_supported = (
            definitions is not None
            and _supported(definitions, REQUEST_METRIC, {"modeldeploymentname", "statuscode"})
        )
        prompt_supported = (
            definitions is not None
            and _supported(definitions, PROMPT_METRIC, {"modeldeploymentname"})
        )
        completion_supported = (
            definitions is not None
            and _supported(definitions, COMPLETION_METRIC, {"modeldeploymentname"})
        )

        for days in WINDOWS:
            start = end - timedelta(days=days)
            row = _base_row(deployment, days, start, end)
            notes = []
            if not is_supported_resource:
                row["usage_status"] = "unsupported"
                row["notes"] = "Azure Monitor per-deployment metrics are unsupported for this resource type"
                rows.append(row)
                continue
            if definitions is None:
                notes.append("Metric definitions unavailable; usage cannot be classified")
            else:
                if not request_supported:
                    notes.append("AzureOpenAIRequests is unavailable or lacks required dimensions")
                if not prompt_supported:
                    notes.append("ProcessedPromptTokens is unavailable for per-deployment usage")
                if not completion_supported:
                    notes.append("GeneratedTokens is unavailable for per-deployment usage")

            request_data = None
            if request_supported:
                response = query(resource_id, days, [REQUEST_METRIC], has_status=True)
                if response is not None:
                    request_data = response.get(REQUEST_METRIC.casefold())
                counts = _request_counts(request_data, deployment.get("name", ""))
                if counts is not None:
                    row["total_requests"] = counts["total"]
                    row["successful_requests"] = counts["successful"]
                    row["failed_requests"] = counts["failed"]
                    row["other_requests"] = counts["other"]
                    if counts["unknown_status"]:
                        row["successful_requests"] = None
                        if counts.get("truncated"):
                            row["total_requests"] = None
                            row["failed_requests"] = None
                            row["other_requests"] = None
                            notes.append("Metric series reached the 1000-series limit; counts may be truncated")
                        else:
                            notes.append("Unrecognized StatusCode category or missing/null success telemetry; "
                                         "successful request count is unknown")
                    else:
                        row["usage_status"] = (
                            "zero_successful_requests"
                            if counts["successful"] == 0 else "active"
                        )
                elif request_data and _metric_failed(request_data):
                    notes.append("AzureOpenAIRequests metric returned an error")
                else:
                    notes.append("No request metric series for this deployment; telemetry is unknown")

            token_metrics = [
                name for name, supported in (
                    (PROMPT_METRIC, prompt_supported),
                    (COMPLETION_METRIC, completion_supported),
                ) if supported
            ]
            if token_metrics:
                response = query(resource_id, days, token_metrics, has_status=False)
                for metric_name, supported, column, label in (
                    (PROMPT_METRIC, prompt_supported, "prompt_tokens", "prompt"),
                    (COMPLETION_METRIC, completion_supported, "completion_tokens", "completion"),
                ):
                    if not supported:
                        continue
                    metric_data = response.get(metric_name.casefold()) if response is not None else None
                    row[column] = _token_total(metric_data, deployment.get("name", ""))
                    if row[column] is None:
                        notes.append(f"No {label} token metric series; token usage is unknown")

            if not request_supported:
                row["usage_status"] = "unsupported" if definitions is not None else "unknown"
            if row["usage_status"] == "unknown" and not notes:
                notes.append("Usage telemetry unavailable")
            row["metric_source"] = "Azure Monitor Metrics API (2023-10-01)"
            row["notes"] = "; ".join(notes)
            rows.append(row)
    return rows
