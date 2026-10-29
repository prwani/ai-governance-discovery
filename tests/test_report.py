import unittest
import json
from html import escape

from report import PILLARS, SECTION_PILLARS, build_sections, render_report


class ReportTests(unittest.TestCase):
    def inventory(self):
        return {
            "foundry_resources": [
                {"id": "/accounts/ai", "name": "<script>alert(1)</script>",
                 "subscription_name": "Subscription", "resource_group": "rg",
                 "public_network_access": "Enabled", "key_based_access": "disabled",
                 "private_endpoint_connections": json.dumps([{
                     "private_endpoint_id": "/privateEndpoints/pe1", "status": "Approved",
                     "group_ids": ["account"], "actions_required": "None",
                 }]),
                 "rai_policies": json.dumps([{
                     "name": "safe-policy", "mode": "Blocking", "base_policy_name": "default",
                     "content_filters": [{"name": "Hate", "enabled": True, "blocking": True,
                                          "severityThreshold": "Medium"}],
                     "custom_blocklist_count": 1,
                 }]),
                 "diagnostic_setting_count": "1",
                 "diagnostic_settings": json.dumps([{
                     "name": "to-logs", "destination_types": ["workspace"],
                     "enabled_log_categories": ["AuditEvent"],
                     "enabled_metric_categories": ["AllMetrics"],
                 }])},
                {"id": "/accounts/ai/projects/p", "name": "p", "subscription_name": "Subscription",
                 "resource_group": "rg", "public_network_access": "", "key_based_access": "allowed",
                 "private_endpoint_connections": "[]", "rai_policies": "[]",
                 "diagnostic_setting_count": "0", "diagnostic_settings": "[]"},
            ],
            "model_deployments": [
                {"id": "/accounts/ai/deployments/a", "resource_id": "/accounts/ai", "name": "a",
                 "rai_policy_name": "safe-policy"},
                {"id": "/accounts/ai/deployments/b", "resource_id": "/accounts/ai", "name": "b"},
            ],
            "apim_resources": [
                {"name": "public-apim", "public_network_access": "Enabled",
                 "subscription_name": "Subscription", "resource_group": "rg",
                 "api_inventory": json.dumps([{"name": "chat", "display_name": "Chat",
                                               "path": "chat", "api_revision": "1",
                                               "api_version": "", "api_type": "http",
                                               "subscription_required": True}]),
                 "product_inventory": json.dumps([{"name": "team", "display_name": "Team",
                                                   "state": "published", "approval_required": True,
                                                   "subscription_required": True,
                                                   "api_ids": ["/apis/chat"]}]),
                 "subscription_inventory": json.dumps([{"name": "team-sub",
                                                        "display_name": "Team subscription",
                                                        "owner_id": "owner",
                                                        "scope": "/products/team",
                                                        "state": "active"}]),
                 "diagnostic_setting_count": "1",
                 "diagnostic_settings": json.dumps([{
                     "name": "apim-logs", "destination_types": ["workspace"],
                     "enabled_log_categories": ["GatewayLogs"],
                     "enabled_metric_categories": [],
                 }])},
                {"name": "private-apim", "public_network_access": "Disabled",
                 "subscription_name": "Subscription", "resource_group": "rg",
                 "api_inventory": "[]", "product_inventory": "[]",
                 "subscription_inventory": "[]", "diagnostic_setting_count": "0",
                 "diagnostic_settings": "[]"},
                {"name": "unknown-apim", "gateway_url": "https://public.example"},
            ],
            "subscriptions": [{
                "subscription_name": "Subscription",
                "policy_assignments": json.dumps([{
                    "display_name": "Allowed locations",
                    "policy_definition_id": "/policyDefinitions/locations",
                    "scope": "/subscriptions/sub", "enforcement_mode": "Default",
                    "effect": "Deny", "parameter_names": ["listOfAllowedLocations"],
                }]),
            }],
            "regional_quotas": [{
                "subscription_name": "Subscription", "location": "eastus",
                "display_name": "GPT usage", "usage_name": "OpenAI.GPT",
                "current_value": "3", "limit": "10", "unit": "Count",
            }],
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

    def test_customer_report_displays_new_inventory_and_groups_by_workbook_pillar(self):
        tables = self.inventory()
        sections = build_sections(tables)
        by_title = {title: rows for title, rows, _, _ in sections}
        self.assertEqual(len(PILLARS), 6)
        self.assertTrue(all(title in SECTION_PILLARS for title, _, _, _ in sections))
        self.assertEqual(by_title["Azure Policy assignments"][0]["effect"], "Deny")
        self.assertEqual(by_title["Private endpoint connections"][0]["status"], "Approved")
        self.assertEqual(by_title["Diagnostic settings coverage"][0]["enabled_logs"],
                         "AuditEvent")
        self.assertTrue(any(row["policy_name"] == "safe-policy"
                            for row in by_title["Foundry RAI policy and deployment configuration"]))
        self.assertTrue(any(row["inventory_type"] == "Product"
                            for row in by_title["APIM APIs, products, and subscriptions"]))
        self.assertEqual(by_title["Regional AI quota usage"][0]["unit"], "Count")

        html = render_report(tables)
        self.assertIn('id="pillar-1"', html)
        self.assertIn('id="pillar-6"', html)
        self.assertIn("#6 Agent Architectures", html)
        self.assertIn("Private endpoint connections", html)
        self.assertIn("Allowed locations", html)
        self.assertIn("GatewayLogs", html)
        self.assertIn("safe-policy", html)
        self.assertIn("team-sub", html)

    def test_report_marks_new_inventory_unknown_for_scans_without_added_columns(self):
        tables = self.inventory()
        for resource in tables["foundry_resources"]:
            resource.pop("private_endpoint_connections", None)
            resource.pop("rai_policies", None)
            resource.pop("diagnostic_setting_count", None)
            resource.pop("diagnostic_settings", None)
        for resource in tables["apim_resources"]:
            resource.pop("api_inventory", None)
            resource.pop("product_inventory", None)
            resource.pop("subscription_inventory", None)
            resource.pop("diagnostic_setting_count", None)
            resource.pop("diagnostic_settings", None)
        html = render_report(tables)
        self.assertIn("Not collected", html)

    def test_report_does_not_render_partial_diagnostic_collection_as_none(self):
        tables = self.inventory()
        resource = tables["foundry_resources"][0]
        resource["diagnostic_settings"] = "[]"
        resource["diagnostic_settings_status"] = "partial"
        rows = next(rows for title, rows, _, _ in build_sections(tables)
                    if title == "Diagnostic settings coverage")
        first = next(row for row in rows if row["name"] == resource["name"])
        self.assertIn("Collection partial", first["destinations"])

    def test_toc_nests_subsections_under_each_pillar_and_links_to_all_targets(self):
        tables = self.inventory()
        sections = build_sections(tables)
        html = render_report(tables)
        toc = html.split('<ul class="toc">', 1)[1].split("</nav>", 1)[0]
        self.assertIn('<header id="top">', html)
        self.assertIn('aria-labelledby="toc-heading"', html)
        for pillar_index, pillar in enumerate(PILLARS, 1):
            entry = toc.split(f'<li><a href="#pillar-{pillar_index}">', 1)[1]
            nested = entry.split("<ul>", 1)[1].split("</ul>", 1)[0]
            expected = [(index, title) for index, (title, _, _, _) in
                        enumerate(sections, 1) if SECTION_PILLARS[title] == pillar]
            self.assertEqual(nested.count("<li>"), len(expected))
            for index, title in expected:
                self.assertIn(f'<a href="#section-{index}">{escape(title)} ', nested)
                self.assertIn(f'id="section-{index}"', html)

    def test_back_to_top_links_at_start_and_end_of_every_section_and_subsection(self):
        tables = self.inventory()
        html = render_report(tables)
        link = '<p class="back-to-top"><a href="#top">Back to top</a></p>'
        sections = build_sections(tables)
        self.assertEqual(html.count(link), 2 * (len(PILLARS) + len(sections)))
        for pillar_index in range(1, len(PILLARS) + 1):
            pillar = html.split(f'id="pillar-{pillar_index}">', 1)[1].split("</section>", 1)[0]
            self.assertIn("</h2>" + link, pillar)
            self.assertTrue(pillar.endswith(link))
        for index in range(1, len(sections) + 1):
            subsection = html.split(f'id="section-{index}">', 1)[1]
            self.assertIn("</h3>" + link, subsection.split('<p class="note">', 1)[0])
            ending = subsection.split(link + "</div>", 1)
            self.assertEqual(len(ending), 2)
