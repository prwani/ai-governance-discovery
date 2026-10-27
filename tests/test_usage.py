import unittest
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from discovery.usage import collect_usage


ACCOUNT_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/"
    "Microsoft.CognitiveServices/accounts/ai"
)


def metric_definition(name, dimensions):
    return {
        "name": {"value": name},
        "primaryAggregationType": "Total",
        "supportedAggregationTypes": ["Total"],
        "dimensions": [{"value": dimension} for dimension in dimensions],
    }


def metric(name, deployment, data, status=None):
    dimensions = [{"name": {"value": "ModelDeploymentName"}, "value": deployment}]
    if status is not None:
        dimensions.append({"name": {"value": "StatusCode"}, "value": status})
    return {
        "name": {"value": name},
        "timeseries": [{"metadatavalues": dimensions, "data": data}],
    }


def points(*totals):
    return [{"timeStamp": f"2026-10-{index + 1:02d}T00:00:00Z", "total": value}
            for index, value in enumerate(totals)]


class FakeClient:
    def __init__(self, definitions, metric_response=None):
        self.definitions = definitions
        self.metric_response = metric_response
        self.calls = []
        self.errors = []

    def get(self, path, api_version):
        self.calls.append((path, api_version))
        if "metricDefinitions" in path:
            return {"value": self.definitions}
        if self.metric_response is None:
            return {"value": []}
        return self.metric_response(path)

    def error(self, scope, operation, message):
        self.errors.append((scope, operation, message))


def definitions():
    return [
        metric_definition("AzureOpenAIRequests", ["ModelDeploymentName", "StatusCode"]),
        metric_definition("ProcessedPromptTokens", ["ModelDeploymentName"]),
        metric_definition("GeneratedTokens", ["ModelDeploymentName"]),
    ]


def deployment(name="chat", resource_id=ACCOUNT_ID):
    return {
        "id": resource_id + "/deployments/" + name,
        "name": name,
        "resource_id": resource_id,
        "subscription_id": "sub",
        "subscription_name": "Subscription",
        "resource_group": "rg",
        "model_name": "example",
        "model_version": "1",
    }


class UsageTests(unittest.TestCase):
    def test_same_account_deployments_reuse_four_queries_and_definition_lookup(self):
        def response(path):
            names = parse_qs(urlsplit(path).query)["metricnames"][0].split(",")
            return {"value": [
                metric(name, deployment_name, points(value),
                       "Successful" if name == "AzureOpenAIRequests" else None)
                for name in names for deployment_name, value in (("chat", 3), ("second", 7))
            ]}

        client = FakeClient(definitions(), response)
        rows = collect_usage(client, [deployment(), deployment("second", ACCOUNT_ID.upper() + "/")],
                             now=datetime(2026, 10, 26, tzinfo=timezone.utc))

        self.assertEqual(len(rows), 4)
        self.assertEqual([row["successful_requests"] for row in rows], [3, 3, 7, 7])
        self.assertEqual([row["prompt_tokens"] for row in rows], [3, 3, 7, 7])
        self.assertEqual(sum("/metrics?" in path for path, _ in client.calls), 4)
        self.assertEqual(sum("metricDefinitions" in path for path, _ in client.calls), 1)
        self.assertTrue(all(version == ("2018-01-01" if "metricDefinitions" in path else "2023-10-01")
                            for path, version in client.calls))

    def test_per_metric_errors_and_missing_metrics_log_errors_and_remain_unknown(self):
        for error_fields in ({"error": {"code": "BadRequest"}}, {"errorCode": "BadRequest"}):
            with self.subTest(error_fields=error_fields):
                def response(path):
                    names = parse_qs(urlsplit(path).query)["metricnames"]
                    if names == ["AzureOpenAIRequests"]:
                        return {"value": [{
                            **metric("AzureOpenAIRequests", "chat", points(0), "Successful"),
                            **error_fields,
                        }]}
                    return {"value": [metric("ProcessedPromptTokens", "chat", points(2))]}

                client = FakeClient(definitions(), response)
                rows = collect_usage(client, [deployment()],
                                     now=datetime(2026, 10, 26, tzinfo=timezone.utc))
                self.assertTrue(all(row["usage_status"] == "unknown" for row in rows))
                self.assertTrue(all(row["successful_requests"] is None for row in rows))
                self.assertTrue(all(row["prompt_tokens"] == 2 for row in rows))
                self.assertTrue(all(row["completion_tokens"] is None for row in rows))
                self.assertEqual(len(client.errors), 4)
                messages = [message for _, _, message in client.errors]
                self.assertTrue(any("AzureOpenAIRequests returned a metric error" in m
                                    for m in messages))
                self.assertTrue(any("GeneratedTokens missing" in m for m in messages))

    def test_null_success_series_with_failed_attempts_does_not_imply_zero_success(self):
        def response(path):
            if parse_qs(urlsplit(path).query)["metricnames"] == ["AzureOpenAIRequests"]:
                return {"value": [
                    metric("AzureOpenAIRequests", "chat", points(None), "Successful"),
                    metric("AzureOpenAIRequests", "chat", points(9), "ClientErrors"),
                ]}
            return {"value": []}

        client = FakeClient(definitions(), response)
        rows = collect_usage(client, [deployment()],
                             now=datetime(2026, 10, 26, tzinfo=timezone.utc))
        self.assertTrue(all(row["usage_status"] == "unknown" for row in rows))
        self.assertTrue(all(row["successful_requests"] is None for row in rows))
        self.assertTrue(all(row["failed_requests"] == 9 for row in rows))

    def test_failed_only_and_null_only_telemetry_are_unknown(self):
        for series in (
            metric("AzureOpenAIRequests", "chat", points(8), "500"),
            metric("AzureOpenAIRequests", "chat", points(None), "Successful"),
        ):
            with self.subTest(series=series):
                client = FakeClient(definitions(), lambda path: {"value": [series]})
                rows = collect_usage(client, [deployment()],
                                     now=datetime(2026, 10, 26, tzinfo=timezone.utc))
                self.assertTrue(all(row["usage_status"] == "unknown" for row in rows))
                self.assertTrue(all(row["successful_requests"] is None for row in rows))

    def test_missing_series_is_unknown_but_explicit_zero_is_flagged(self):
        def response(path):
            params = parse_qs(urlsplit(path).query)
            if params["metricnames"] == ["AzureOpenAIRequests"]:
                if "2026-09-26" in params["timespan"][0]:
                    return {"value": []}
                return {"value": [metric(
                    "AzureOpenAIRequests", "chat", points(0, 0), "Successful"
                )]}
            return {"value": []}

        client = FakeClient(definitions(), response)
        rows = collect_usage(
            client, [deployment()], now=datetime(2026, 10, 26, tzinfo=timezone.utc)
        )

        self.assertEqual([row["window_days"] for row in rows], [7, 30])
        self.assertEqual(rows[0]["usage_status"], "zero_successful_requests")
        self.assertEqual(rows[0]["successful_requests"], 0)
        self.assertEqual(rows[0]["total_requests"], 0)
        self.assertEqual(rows[1]["usage_status"], "unknown")
        self.assertIsNone(rows[1]["successful_requests"])
        self.assertIn("telemetry is unknown", rows[1]["notes"])

    def test_request_failures_and_token_series_are_summed_without_window_overlap(self):
        def response(path):
            params = parse_qs(urlsplit(path).query)
            metric_names = params["metricnames"][0].split(",")
            is_short_window = "2026-10-19" in params["timespan"][0]
            if metric_names == ["AzureOpenAIRequests"]:
                if is_short_window:
                    return {"value": [
                        metric("AzureOpenAIRequests", "chat", points(2, 3), "Successful"),
                        metric("AzureOpenAIRequests", "chat", points(4), "ClientErrors"),
                        metric("AzureOpenAIRequests", "chat", points(1), "Server Errors"),
                    ]}
                return {"value": [
                    metric("AzureOpenAIRequests", "chat", points(20), "Successful"),
                    metric("AzureOpenAIRequests", "chat", points(6), "ClientErrors"),
                ]}
            if is_short_window:
                return {"value": [
                    metric("ProcessedPromptTokens", "chat", points(10, 20)),
                    metric("ProcessedPromptTokens", "chat", points(5)),
                    metric("GeneratedTokens", "chat", points(7, 8)),
                ]}
            return {"value": [
                metric("ProcessedPromptTokens", "chat", points(100)),
                metric("GeneratedTokens", "chat", points(30)),
            ]}

        client = FakeClient(definitions(), response)
        rows = collect_usage(
            client, [deployment()], now=datetime(2026, 10, 26, tzinfo=timezone.utc)
        )

        short, long = rows
        self.assertEqual(short["usage_status"], "active")
        self.assertEqual(short["successful_requests"], 5)
        self.assertEqual(short["failed_requests"], 5)
        self.assertEqual(short["other_requests"], 0)
        self.assertEqual(short["total_requests"], 10)
        self.assertEqual(short["prompt_tokens"], 35)
        self.assertEqual(short["completion_tokens"], 15)
        self.assertEqual(long["total_requests"], 26)
        self.assertEqual(long["prompt_tokens"], 100)
        self.assertEqual(long["completion_tokens"], 30)

        metric_calls = [(path, version) for path, version in client.calls
                        if "/metrics?" in path]
        self.assertEqual(len(metric_calls), 4)
        self.assertTrue(all(version == "2023-10-01" for _, version in metric_calls))
        self.assertTrue(any("%24filter" in path and "%27%2A%27" in path
                            for path, _ in metric_calls))
        self.assertTrue(all("top=1000" in path for path, _ in metric_calls))

    def test_unknown_status_category_prevents_zero_success_classification(self):
        client = FakeClient(definitions(), lambda path: {"value": [
            metric("AzureOpenAIRequests", "chat", points(4), "Unclassified")
        ]} if parse_qs(urlsplit(path).query)["metricnames"] == ["AzureOpenAIRequests"]
             else {"value": []})

        row = collect_usage(client, [deployment()], now=datetime(2026, 10, 26, tzinfo=timezone.utc))[0]

        self.assertEqual(row["usage_status"], "unknown")
        self.assertIsNone(row["successful_requests"])
        self.assertEqual(row["other_requests"], 4)
        self.assertIn("Unrecognized StatusCode", row["notes"])

    def test_series_limit_makes_counts_unknown_instead_of_reporting_partial_zero(self):
        sample = metric("AzureOpenAIRequests", "chat", points(0), "Successful")
        sample["timeseries"] = sample["timeseries"] * 1000
        client = FakeClient(definitions(), lambda path: {"value": [sample]}
                            if parse_qs(urlsplit(path).query)["metricnames"] == ["AzureOpenAIRequests"]
                            else {"value": []})

        row = collect_usage(client, [deployment()],
                            now=datetime(2026, 10, 26, tzinfo=timezone.utc))[0]

        self.assertEqual(row["usage_status"], "unknown")
        self.assertIsNone(row["successful_requests"])
        self.assertIsNone(row["total_requests"])
        self.assertIn("1000-series limit", row["notes"])

    def test_unsupported_ml_deployment_has_two_rows_and_makes_no_metric_calls(self):
        workspace_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws"
        client = FakeClient([])

        rows = collect_usage(client, [deployment("ml", workspace_id)],
                             now=datetime(2026, 10, 26, tzinfo=timezone.utc))

        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["usage_status"] == "unsupported" for row in rows))
        self.assertTrue(all(row["total_requests"] is None for row in rows))
        self.assertEqual(client.calls, [])

    def test_missing_request_metric_definition_is_unsupported_not_zero(self):
        client = FakeClient([
            metric_definition("ProcessedPromptTokens", ["ModelDeploymentName"]),
            metric_definition("GeneratedTokens", ["ModelDeploymentName"]),
        ])

        rows = collect_usage(client, [deployment()], now=datetime(2026, 10, 26, tzinfo=timezone.utc))

        self.assertEqual([row["usage_status"] for row in rows], ["unsupported", "unsupported"])
        self.assertTrue(all(row["successful_requests"] is None for row in rows))
        self.assertTrue(all("AzureOpenAIRequests is unavailable" in row["notes"] for row in rows))
        self.assertFalse(any(
            "/metrics?" in path
            and parse_qs(urlsplit(path).query).get("metricnames") == ["AzureOpenAIRequests"]
            for path, _ in client.calls
        ))


if __name__ == "__main__":
    unittest.main()
