import unittest

from report import build_sections, render_report


class ReportTests(unittest.TestCase):
    def inventory(self):
        return {
            "foundry_resources": [
                {"id": "/accounts/ai", "name": "<script>alert(1)</script>",
                 "subscription_name": "Subscription", "resource_group": "rg",
                 "public_network_access": "Enabled", "key_based_access": "disabled"},
                {"id": "/accounts/ai/projects/p", "name": "p", "subscription_name": "Subscription",
                 "resource_group": "rg", "public_network_access": "", "key_based_access": "allowed"},
            ],
            "model_deployments": [
                {"id": "/accounts/ai/deployments/a", "resource_id": "/accounts/ai", "name": "a"},
                {"id": "/accounts/ai/deployments/b", "resource_id": "/accounts/ai", "name": "b"},
            ],
            "apim_resources": [
                {"name": "public-apim", "public_network_access": "Enabled"},
                {"name": "private-apim", "public_network_access": "Disabled"},
                {"name": "unknown-apim", "gateway_url": "https://public.example"},
            ],
            "apim_foundry_mappings": [
                {"match_status": "deployment_confirmed", "deployment_id": "/ACCOUNTS/AI/DEPLOYMENTS/A"},
                {"match_status": "resource_only", "foundry_resource_id": "/ACCOUNTS/AI",
                 "apim_name": "apim", "backend_name": "account"},
            ],
            "foundry_role_assignments": [],
            "scan_errors": [],
            "summary": {"status": "complete", "tenant_id": "tenant"},
        }

    def test_filters_require_explicit_enabled_status(self):
        sections = build_sections(self.inventory())
        self.assertEqual(len(sections[0][1]), 1)
        self.assertEqual(sections[0][1][0]["id"], "/accounts/ai")
        self.assertEqual(sections[1][1][0]["name"], "p")
        self.assertEqual([r["name"] for r in sections[2][1]], ["public-apim"])
        self.assertEqual(len(sections[0][2]), 3)
        self.assertEqual(len(sections[1][2]), 3)

    def test_account_only_mapping_is_uncertain_not_a_confirmed_deployment(self):
        rows = build_sections(self.inventory())[4][1]
        self.assertEqual([r["name"] for r in rows], ["b"])
        self.assertIn("unconfirmed", rows[0]["mapping_status"])
        self.assertIn("resource_only", rows[0]["related_backends"])

    def test_user_and_service_principal_assignments_group_roles_without_group_expansion(self):
        tables = self.inventory()
        base = {
            "foundry_resource_id": "/accounts/ai", "foundry_resource_name": "ai",
            "subscription_name": "Subscription", "resource_group": "rg",
            "principal_id": "user", "principal_type": "User", "role_name": "Reader",
            "assignment_scope": "/subscriptions/sub", "assignment_relationship": "inherited",
        }
        tables["foundry_role_assignments"] = [
            base, {**base, "role_name": "Foundry User", "condition": "a < b"},
            {**base, "principal_id": "sp", "principal_type": "ServicePrincipal"},
            {**base, "principal_id": "group", "principal_type": "Group"},
        ]
        rows = build_sections(tables)[3][1]
        self.assertEqual(len(rows), 2)
        user = next(r for r in rows if r["principal_id"] == "user")
        self.assertEqual(set(user["roles"].splitlines()), {"Reader", "Foundry User"})
        self.assertIn("condition: a < b", user["assignments"])

    def test_html_escapes_inventory_and_marks_unknown_and_incomplete_data(self):
        tables = self.inventory()
        tables["summary"]["status"] = "partial"
        tables["scan_errors"] = [{"message": "Forbidden"}]
        html = render_report(tables)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("APIM public access: 1", html)
        self.assertIn("Scan status: partial", html)
        self.assertIn("Recorded collection errors: 1", html)
        self.assertIn("not proof", html)
        self.assertIn('Content-Security-Policy', html)

    def test_usage_zero_success_is_distinct_from_unknown_and_failed_attempts(self):
        tables = self.inventory()
        base = {"resource_id": "/accounts/ai", "deployment_name": "a", "window_days": 7}
        tables["model_usage"] = [
            {**base, "usage_status": "zero_successful_requests", "successful_requests": 0,
             "failed_requests": 20},
            {**base, "window_days": 30, "usage_status": "unknown",
             "notes": "No data returned"},
            {**base, "deployment_name": "b", "usage_status": "active", "successful_requests": 5},
        ]
        sections = build_sections(tables)
        zero = next(section for section in sections if section[0] ==
                    "Model deployments with zero successful requests")
        self.assertEqual(len(zero[1]), 1)
        self.assertEqual(zero[1][0]["failed_requests"], 20)
        unknown = next(section for section in sections if section[0] ==
                       "Model usage requiring verification")
        self.assertEqual(len(unknown[1]), 1)
        self.assertIn("<td>0</td>", render_report(tables))

    def test_retirement_flags_past_and_soon_not_unlisted_or_long_term(self):
        tables = self.inventory()
        base = {"resource_id": "/accounts/ai", "deployment_name": "a"}
        tables["model_retirements"] = [
            {**base, "retirement_status": "past_retirement_date"},
            {**base, "retirement_status": "retiring_soon"},
            {**base, "retirement_status": "scheduled"},
            {**base, "retirement_status": "not_listed"},
        ]
        sections = build_sections(tables)
        flagged = next(section for section in sections if section[0] ==
                       "Model deployments past or nearing scheduled retirement")
        self.assertEqual(len(flagged[1]), 2)
        unresolved = next(section for section in sections if section[0] ==
                          "Model retirement matches requiring verification")
        self.assertEqual(len(unresolved[1]), 1)
