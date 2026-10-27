import csv
import io
import json
import unittest
from pathlib import Path
from unittest.mock import call, mock_open, patch
from contextlib import redirect_stderr, redirect_stdout

import scan
from discovery import apim, azure, foundry


SUBSCRIPTION = {
    "id": "sub-1",
    "name": "Test subscription",
    "tenantId": "tenant-1",
}
ACCOUNT_ID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai"


class AzureClientTests(unittest.TestCase):
    @patch("discovery.azure.cli_json")
    def test_list_follows_next_link_and_stops_on_failed_page(self, cli_json):
        next_link = "https://management.example/subscriptions/sub-1/resources?skip=2"
        cli_json.side_effect = [
            {"value": [{"name": "first"}], "nextLink": next_link},
            RuntimeError("Forbidden"),
        ]
        client = azure.AzureClient("https://management.example/")

        self.assertEqual(client.list("/subscriptions/sub-1/resources", "v1"), [{"name": "first"}])
        self.assertEqual(cli_json.call_args_list, [
            call(["rest", "--method", "get", "--url",
                  "https://management.example/subscriptions/sub-1/resources?api-version=v1"]),
            call(["rest", "--method", "get", "--url", next_link + "&api-version=v1"]),
        ])
        self.assertEqual(client.errors[-1]["operation"], "GET")

    @patch("discovery.azure.cli_json")
    def test_list_detects_repeated_next_link(self, cli_json):
        repeated = "https://management.example/resources?api-version=v1"
        cli_json.return_value = {"value": [{"name": "first"}], "nextLink": repeated}
        client = azure.AzureClient("https://management.example")

        self.assertEqual(client.list(repeated, "v1"), [{"name": "first"}])
        self.assertEqual(cli_json.call_count, 1)
        self.assertIn("Repeated pagination link", client.errors[-1]["message"])

    def test_safe_url_removes_credentials_and_unapproved_query_values(self):
        value = ("https://user:password@models.example/path"
                 "?api-key=secret&deployment=chat&api-version=2025-01-01#fragment")

        self.assertEqual(
            azure.safe_url(value),
            "https://models.example/path?deployment=chat&api-version=2025-01-01",
        )
        self.assertEqual(
            azure.safe_url("https://models.example/path?secret=value#fragment"),
            "https://models.example/path",
        )

    def test_safe_url_keeps_named_value_evidence_without_query_or_fragment(self):
        self.assertEqual(
            azure.safe_url("https://{{gateway}}.example/path?key=hidden#part"),
            "https://{{gateway}}.example/path",
        )
        self.assertEqual(
            azure.safe_url("https://user:password@{{gateway}}.example/path?key=hidden"),
            "https://{{gateway}}.example/path",
        )


class ScanOutputTests(unittest.TestCase):
    def test_csv_writer_escapes_formula_values(self):
        handle = mock_open()
        with patch.object(Path, "open", handle):
            scan.write_csv(Path("inventory.csv"), [{"name": "  =1+1", "note": "ordinary"}],
                           ["name", "note"])

        contents = "".join(write.args[0] for write in handle().write.call_args_list)
        rows = list(csv.DictReader(io.StringIO(contents)))
        self.assertEqual(rows[0], {"name": "'  =1+1", "note": "ordinary"})

    @patch("scan.write_csv")
    @patch.object(Path, "write_text")
    @patch.object(Path, "mkdir")
    @patch("scan.AzureClient")
    @patch("scan.cli_json")
    def test_runner_scans_only_enabled_subscriptions_in_current_tenant(
            self, cli_json, client_class, mkdir, write_text, write_csv):
        cli_json.side_effect = [
            {"tenantId": "TENANT-1"},
            {"endpoints": {"resourceManager": "https://management.example"}},
        ]
        client = client_class.return_value
        client.list.return_value = [
            {"subscriptionId": "sub-1", "displayName": "Test subscription",
             "tenantId": "tenant-1", "state": "Enabled"},
            {"subscriptionId": "disabled", "displayName": "Disabled",
             "tenantId": "tenant-1", "state": "Disabled"},
            {"subscriptionId": "other", "displayName": "Other tenant",
             "tenantId": "tenant-2", "state": "Enabled"},
        ]
        client.errors = []
        client.requests = []
        client.error.side_effect = lambda *args: client.errors.append({"scope": args[0]})
        output = Path("unused-output")
        with patch("discovery.foundry.collect_foundry", return_value=([], [])) as collect_foundry, \
                patch("discovery.foundry.collect_quotas",
                      return_value=[{"usage_name": "test-quota"}]), \
                patch("discovery.rbac.collect_role_assignments", return_value=[]) as collect_rbac, \
                patch("discovery.usage.collect_usage", return_value=[]) as collect_usage, \
                patch("discovery.retirements.collect_retirements",
                      return_value=[]) as collect_retirements, \
                patch("discovery.apim.collect_apim", return_value=([], [])), \
                patch("discovery.apim.map_backends", return_value=[]), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = scan.run(output)

        self.assertEqual(result, 2)
        collect_foundry.assert_called_once_with(client, {**SUBSCRIPTION, "tenantId": "tenant-1",
                                                         "state": "Enabled"})
        client.error.assert_called_once_with(
            "disabled", "subscription",
            "Subscription is not Enabled; not scanned",
        )
        client.list.assert_called_once_with("/subscriptions", "2022-12-01")
        collect_rbac.assert_called_once_with(client, [], {})
        collect_usage.assert_called_once()
        collect_retirements.assert_called_once()
        self.assertEqual(collect_retirements.call_args.kwargs["warning_days"], 90)
        self.assertEqual(collect_usage.call_args.kwargs["now"],
                         collect_retirements.call_args.kwargs["now"])
        mkdir.assert_called_once_with(parents=True, exist_ok=False)
        self.assertTrue(write_csv.called)
        self.assertTrue(write_text.called)
        exported_files = {invocation.args[0].name for invocation in write_csv.call_args_list}
        self.assertEqual(exported_files, {
            "subscriptions.csv", "foundry_resources.csv", "model_deployments.csv",
            "apim_resources.csv", "apim_backends.csv", "apim_foundry_mappings.csv",
            "scan_errors.csv", "regional_quotas.csv", "foundry_role_assignments.csv",
            "model_usage.csv", "model_retirements.csv",
        })
        summary = json.loads(write_text.call_args.args[0])
        self.assertEqual(summary["counts"]["regional_quotas"], 1)
        quota_export = next(invocation for invocation in write_csv.call_args_list
                            if invocation.args[0].name == "regional_quotas.csv")
        self.assertEqual(quota_export.args[1], [{"usage_name": "test-quota"}])


class FoundryTests(unittest.TestCase):
    def test_key_access_reflects_explicit_auth_setting_without_guessing(self):
        resource = {"id": ACCOUNT_ID, "name": "ai", "properties": {}}
        for setting, expected in ((False, "allowed"), (True, "disabled"),
                                  (None, "unknown"), ("false", "unknown")):
            with self.subTest(setting=setting):
                resource["properties"] = {"disableLocalAuth": setting}
                row = foundry.resource_row(resource, SUBSCRIPTION)
                self.assertEqual(row["key_based_access"], expected)
                self.assertEqual(row["disable_local_auth"],
                                 setting if isinstance(setting, bool) else "")
        resource["properties"] = {}
        self.assertEqual(foundry.resource_row(resource, SUBSCRIPTION)["key_based_access"], "unknown")

    def test_project_key_access_uses_parent_account_setting(self):
        account = {"id": ACCOUNT_ID, "properties": {"disableLocalAuth": True}}
        project = {"id": ACCOUNT_ID + "/projects/project", "name": "project",
                   "properties": {"disableLocalAuth": False}}
        row = foundry.resource_row(project, SUBSCRIPTION, ACCOUNT_ID, account)
        self.assertEqual(row["key_based_access"], "disabled")
        self.assertEqual(row["key_based_access_source_resource_id"], ACCOUNT_ID)

    def test_token_limit_uses_token_rules_not_request_limits(self):
        rules = [
            {"key": "Requests", "count": 1200, "renewalPeriod": 60},
            {"key": "Tokens", "count": 600, "renewalPeriod": 60},
            {"key": "token", "count": 900, "renewalPeriod": 90},
            {"key": "token", "count": 10000, "renewalPeriod": 0},
        ]
        self.assertEqual(foundry.token_limit(rules), 600)
        self.assertEqual(foundry.token_limit([{"key": "Requests", "count": 50,
                                               "renewalPeriod": 1}]), "")

    def test_model_metadata_supports_allocated_tpm_without_regional_quota_attributes(self):
        deployment = {
            "id": ACCOUNT_ID + "/deployments/chat",
            "name": "chat",
            "sku": {"name": "Standard", "capacity": 3},
            "properties": {
                "model": {"name": "gpt-example", "version": "1", "format": "OpenAI"},
                "rateLimits": [{"key": "Tokens", "count": 60000, "renewalPeriod": 60}],
            },
        }
        account = {
            "id": ACCOUNT_ID, "name": "ai", "kind": "OpenAI", "location": "eastus",
            "properties": {"endpoint": "https://ai.example"},
        }
        model = {"model": {
            "name": "gpt-example", "version": "1", "format": "OpenAI",
            "skus": [{"name": "standard", "usageName": "GPT-Example-Standard",
                      "capacity": {"maximum": 120},
                      "rateLimits": [{"key": "token", "count": 6000, "renewalPeriod": 60}]}],
        }}

        class FakeClient:
            def list(self, path, api_version):
                if path.endswith("/accounts"):
                    return [account]
                if path.endswith("/models"):
                    return [model]
                if path.endswith("/deployments"):
                    return [deployment, {
                        **deployment, "id": ACCOUNT_ID + "/deployments/fallback", "name": "fallback",
                        "properties": {"model": deployment["properties"]["model"]},
                    }]
                if path.endswith("/workspaces"):
                    return []
                raise AssertionError(f"Unexpected list path: {path}")

        resources, deployments = foundry.collect_foundry(FakeClient(), SUBSCRIPTION)
        self.assertEqual(resources[0]["id"], ACCOUNT_ID)
        self.assertEqual(deployments[0]["allocated_tpm"], 60000)
        self.assertEqual(deployments[1]["allocated_tpm"], 18000)
        self.assertIn("account.models.skus", deployments[1]["tpm_source"])
        for row in deployments:
            self.assertFalse(any("quota" in key for key in row))
            self.assertNotIn("model_max_capacity", row)

    def test_regional_quotas_keep_native_units_without_deployment_join(self):
        resource = {"type": "Microsoft.CognitiveServices/accounts", "location": "eastus"}

        class FakeClient:
            def list(self, path, api_version):
                self.path = path
                return [{"name": {"value": "OpenAI.Standard.example", "localizedValue": "Example"},
                         "currentValue": 12, "limit": 100, "unit": "Count"}]

        client = FakeClient()
        rows = foundry.collect_quotas(client, SUBSCRIPTION, [resource, resource])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["limit"], 100)
        self.assertEqual(rows[0]["current_value"], 12)
        self.assertEqual(rows[0]["unit"], "Count")
        self.assertEqual(rows[0]["usage_name"], "OpenAI.Standard.example")
        self.assertEqual(rows[0]["location"], "eastus")


class ApiManagementMappingTests(unittest.TestCase):
    def test_consumption_skips_unsupported_workspaces_but_lists_backends(self):
        service_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim"

        class FakeClient:
            def list(self, path, api_version):
                if path.endswith("/service"):
                    return [{"id": service_id, "name": "apim", "sku": {"name": "Consumption"},
                             "properties": {"publicNetworkAccess": "Enabled"}}]
                if path == service_id + "/backends":
                    return [{"id": path + "/b1", "name": "b1", "properties": {
                        "url": "https://ai.example", "credentials": {"secret": "must-not-export"},
                    }}]
                raise AssertionError("Unexpected or unsupported request: " + path)

        services, backends = apim.collect_apim(FakeClient(), SUBSCRIPTION)
        self.assertEqual(services[0]["workspace_inventory_status"], "not_supported_by_tier")
        self.assertEqual(services[0]["public_network_access"], "Enabled")
        self.assertEqual(backends[0]["url"], "https://ai.example")
        self.assertNotIn("must-not-export", json.dumps(backends))

    def setUp(self):
        self.resource = {
            "id": ACCOUNT_ID, "name": "ai",
            "type": "Microsoft.CognitiveServices/accounts",
            "endpoint": "https://ai.example",
            "endpoints": json.dumps({"openai": "https://ai.example"}),
        }
        self.deployment = {
            "id": ACCOUNT_ID + "/deployments/chat",
            "name": "chat", "resource_id": ACCOUNT_ID,
        }

    def backend(self, url, resource_id=""):
        return {"id": "/subscriptions/sub-1/apim/service/backends/b1", "name": "b1",
                "apim_id": "/subscriptions/sub-1/apim/service", "apim_name": "apim",
                "url": url, "resource_id": resource_id, "backend_type": "Single",
                "pool_members": "[]"}

    def test_arm_ids_are_case_insensitive_and_deployment_url_confirms_match(self):
        backend = self.backend("https://ai.example/openai/deployments/CHAT",
                               ACCOUNT_ID.upper())
        result = apim.map_single(backend, [self.resource], [self.deployment])[0]

        self.assertEqual(apim.arm_id(ACCOUNT_ID.upper()), apim.arm_id(ACCOUNT_ID))
        self.assertEqual(result["match_status"], "deployment_confirmed")
        self.assertEqual(result["deployment_id"], self.deployment["id"])

    def test_account_only_backend_is_resource_only(self):
        result = apim.map_single(self.backend("https://ai.example"), [self.resource],
                                 [self.deployment])[0]
        self.assertEqual(result["match_status"], "resource_only")
        self.assertEqual(result["deployment_id"], "")

    def test_query_deployment_selector_and_unknown_deployment(self):
        selected = apim.map_single(
            self.backend("https://ai.example/invoke?deployment=chat"), [self.resource],
            [self.deployment],
        )[0]
        missing = apim.map_single(
            self.backend("https://ai.example/invoke?deployment=other"), [self.resource],
            [self.deployment],
        )[0]
        self.assertEqual(selected["match_status"], "deployment_confirmed")
        self.assertEqual(missing["match_status"], "deployment_not_found")

    def test_ambiguous_resource_and_unresolved_named_value_are_not_guessed(self):
        duplicate = {**self.resource, "id": self.resource["id"] + "2", "name": "ai2"}
        ambiguous = apim.map_single(self.backend("https://ai.example"), [self.resource, duplicate],
                                    [self.deployment])[0]
        unresolved = apim.map_single(
            self.backend("https://{{backend-host}}/openai"), [], [],
        )[0]
        self.assertEqual(ambiguous["match_status"], "ambiguous_resource")
        self.assertEqual(unresolved["match_status"], "unresolved_named_value")

    def test_pool_members_expand_to_target_and_cycles_are_reported(self):
        target = self.backend("https://ai.example/openai/deployments/chat", ACCOUNT_ID)
        target["id"] = "/subscriptions/sub-1/apim/service/backends/target"
        pool = self.backend("")
        pool.update({"id": "/subscriptions/sub-1/apim/service/backends/pool",
                     "backend_type": "Pool",
                     "pool_members": json.dumps([{"id": "target"}])})
        expanded = apim.map_backends([pool, target], [self.resource], [self.deployment])
        root_result = next(row for row in expanded if row["backend_id"] == pool["id"])
        self.assertEqual(root_result["match_status"], "deployment_confirmed")
        self.assertTrue(root_result["match_basis"].startswith("pool_member:target;"))

        first = self.backend("")
        second = self.backend("")
        first.update({"id": "/subscriptions/sub-1/apim/service/backends/first",
                      "backend_type": "Pool"})
        second.update({"id": "/subscriptions/sub-1/apim/service/backends/second",
                       "backend_type": "Pool"})
        first["pool_members"] = json.dumps([{"id": second["id"]}])
        second["pool_members"] = json.dumps([{"id": first["id"]}])
        cycles = apim.map_backends([first, second], [], [])
        self.assertTrue(any(row["match_status"] == "pool_cycle" for row in cycles))

    def test_workspace_serverless_endpoint_hostname_confirms_deployment(self):
        workspace_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws"
        endpoint_id = workspace_id + "/serverlessEndpoints/ep"
        endpoint = {
            "id": endpoint_id, "name": "ep",
            "properties": {"inferenceEndpoint": {"uri": "https://inference.example/score"}},
        }

        class FakeClient:
            def list(self, path, api_version):
                if path.endswith("/accounts"):
                    return []
                if path.endswith("/workspaces"):
                    return [{"id": workspace_id, "name": "ws",
                             "type": "Microsoft.MachineLearningServices/workspaces"}]
                if path.endswith("/serverlessEndpoints"):
                    return [endpoint]
                if path.endswith(("/onlineEndpoints", "/batchEndpoints")):
                    return []
                raise AssertionError(f"Unexpected list path: {path}")

        resources, deployments = foundry.collect_foundry(FakeClient(), SUBSCRIPTION)
        result = apim.map_single(
            self.backend("https://inference.example/score"), resources, deployments,
        )[0]
        self.assertEqual(result["match_status"], "deployment_confirmed")
        self.assertEqual(result["deployment_id"], endpoint_id)
        self.assertEqual(result["foundry_resource_id"], workspace_id)


if __name__ == "__main__":
    unittest.main()
