import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
from unittest.mock import Mock, patch
from urllib.error import URLError

from discovery import retirements


def schedule(rows, publisher="Azure OpenAI"):
    return (
        "# Model retirement schedule\n\n### " + publisher + "\n\n"
        "| Model | Version | Lifecycle | Retirement date | Replacement |\n"
        "| --- | --- | --- | --- | --- |\n" + rows
    )


def deployment(name="model-a", version="001", **extra):
    return {
        "id": "/subscriptions/sub/accounts/account/deployments/chat", "name": "chat",
        "resource_id": "/subscriptions/sub/accounts/account",
        "subscription_id": "sub", "subscription_name": "Test", "tenant_id": "tenant",
        "model_name": name, "model_version": version, "model_format": "OpenAI", **extra,
    }


class RetirementTests(unittest.TestCase):
    def collect(self, source, deployments, **kwargs):
        client = Mock()
        with patch.object(retirements, "download_schedule", return_value=source):
            rows = retirements.collect_retirements(
                client, deployments, now=datetime(2026, 1, 1, tzinfo=timezone.utc), **kwargs)
        client.error.assert_not_called()
        return rows

    def test_dates_and_inclusive_ninety_day_boundary_preserve_inventory(self):
        source = schedule(
            "| past | 001 | GA | 2025-12-31 | new-model |\n"
            "| today | 001 | GA | 2026-01-01 | — |\n"
            "| boundary | 001 | GA | 2026-04-01 | — |\n"
            "| future | 001 | GA | 2026-04-02 | — |\n")
        inputs = [deployment(name) for name in ("past", "today", "boundary", "future")]
        rows = self.collect(source, inputs)
        self.assertEqual([r["retirement_status"] for r in rows],
                         ["past_retirement_date", "retiring_soon", "retiring_soon", "scheduled"])
        self.assertEqual([r["days_to_retirement"] for r in rows], [-1, 0, 90, 91])
        self.assertEqual(rows[0]["replacement"], "new-model")
        self.assertIn("do not prove", rows[0]["notes"])
        for original, row in zip(inputs, rows):
            self.assertEqual({k: row[k] for k in original}, original)
            self.assertEqual(row["source_url"], retirements.SOURCE_URL)
            self.assertTrue(row["schedule_retrieved_at"])
            self.assertEqual(row["warning_days"], 90)

    def test_exact_case_insensitive_matches_without_version_guessing(self):
        source = schedule("| Model-A | 001 | GA | — | — |\n| model-a-mini | 1 | GA | — | — |")
        rows = self.collect(source, [
            deployment("  MODEL-A  ", "001"), deployment(version="1"),
            deployment(version=""), deployment("model"), deployment("model-a.ft-custom"),
        ])
        self.assertEqual([r["retirement_status"] for r in rows],
                         ["no_date_published", "version_not_listed", "version_not_listed",
                          "not_listed", "not_listed"])
        self.assertEqual(rows[0]["retirement_date"], "")
        self.assertEqual(rows[0]["days_to_retirement"], "")
        self.assertTrue(all(row["match_evidence"] == "[]" for row in rows[1:]))

    def test_output_has_deployment_aliases_without_unrelated_inventory_metadata(self):
        original = deployment(resource_group="test-rg", allocated_tpm=6000,
                              endpoint="https://example.invalid", rate_limits="[]")
        row = self.collect(
            schedule("| model-a | 001 | GA | — | — |"), [original])[0]
        self.assertEqual(row["deployment_id"], original["id"])
        self.assertEqual(row["deployment_name"], original["name"])
        self.assertEqual(row["resource_group"], "test-rg")
        self.assertEqual(row["resource_id"], original["resource_id"])
        self.assertEqual(row["subscription_id"], original["subscription_id"])
        self.assertEqual(row["model_name"], original["model_name"])
        self.assertNotIn("allocated_tpm", row)
        self.assertNotIn("endpoint", row)
        self.assertNotIn("rate_limits", row)

    def test_dashed_schedule_version_is_not_a_wildcard(self):
        source = schedule("| model-a | — | GA | 2026-04-02 | — |")
        rows = self.collect(source, [deployment(version="1"), deployment(version=""),
                                     deployment(version="—")])
        self.assertEqual([r["retirement_status"] for r in rows],
                         ["version_not_listed", "version_not_listed", "scheduled"])

    def test_duplicate_conflicting_dates_are_ambiguous_not_arbitrarily_selected(self):
        source = schedule(
            "| gpt-realtime-mini | 2025-10-06 | GA | 2027-04-06 | — |\n"
            "| gpt-realtime-mini | 2025-10-06 | GA | 2026-09-21 | — |")
        row = self.collect(source, [deployment("gpt-realtime-mini", "2025-10-06")])[0]
        self.assertEqual(row["retirement_status"], "ambiguous")
        self.assertEqual(row["retirement_date"], "")
        self.assertEqual(row["days_to_retirement"], "")
        self.assertEqual({e["retirement_date"] for e in json.loads(row["match_evidence"])},
                         {"2027-04-06", "2026-09-21"})

    def test_identical_duplicates_do_not_create_conflicts(self):
        source = schedule("| model-a | 001 | GA | 2026-04-02 | — |\n" * 2)
        row = self.collect(source, [deployment()])[0]
        self.assertEqual(row["retirement_status"], "scheduled")

    def test_publisher_disambiguation_and_generic_aiservices_format(self):
        source = (schedule("| model-a | 001 | GA | 2026-04-02 | — |\n")
                  + "\n### Microsoft\n\n"
                  "| Model | Version | Lifecycle | Retirement date | Replacement |\n"
                  "| --- | --- | --- | --- | --- |\n"
                  "| model-a | 001 | GA | 2025-12-31 | — |\n")
        rows = self.collect(source, [
            deployment(model_publisher="openai", model_format="AIServices"),
            deployment(model_publisher="Microsoft", model_format="AIServices"),
            deployment(model_publisher="Unrelated"),
            deployment(model_format="AIServices"),
        ])
        self.assertEqual([r["retirement_status"] for r in rows],
                         ["scheduled", "past_retirement_date", "not_listed", "ambiguous"])

    def test_html_inline_markup_and_fine_tuning_deployment_not_training(self):
        source = (
            "<html><head><title>Model retirement schedule - Microsoft Learn</title></head>"
            "<body><h2>Foundry Models sold by Azure</h2><h3>Azure OpenAI</h3>"
            "<table><tr><th>Model</th><th>Version</th><th>Lifecycle</th>"
            "<th>Retirement date</th><th>Replacement</th></tr>"
            "<tr><td><code>model-a</code></td><td>001</td><td>GA</td>"
            "<td>2025-12-31</td><td>new&amp;better</td></tr></table>"
            "<h4>Fine-tuned models</h4><table><tr><th>Model</th><th>Version</th>"
            "<th>Training retirement date</th><th>Deployment retirement date</th></tr>"
            "<tr><td>model-a</td><td>001</td>"
            "<td>No earlier than 2026-01-01<sup>1</sup></td>"
            "<td>2026-04-02</td></tr></table></body></html>")
        rows = self.collect(source, [deployment(), deployment(is_fine_tuned=True),
                                     deployment("model-a.ft-custom")])
        self.assertEqual([r["retirement_status"] for r in rows],
                         ["past_retirement_date", "scheduled", "not_listed"])
        self.assertEqual(rows[0]["replacement"], "new&better")
        self.assertEqual(rows[1]["retirement_date"], "2026-04-02")
        self.assertEqual(rows[1]["publisher"], "Azure OpenAI")
        self.assertIn("training_retirement_date", json.loads(rows[1]["match_evidence"])[0])

    def test_download_failure_returns_unknown_for_every_deployment_and_logs_error(self):
        for failure in (URLError("offline"), IncompleteRead(b"partial")):
            with self.subTest(failure=failure):
                client = Mock()
                with patch.object(retirements, "download_schedule", side_effect=failure):
                    rows = retirements.collect_retirements(
                        client, [deployment(), deployment("other")])
                self.assertEqual(len(rows), 2)
                self.assertTrue(all(r["retirement_status"] == "schedule_unavailable" for r in rows))
                self.assertTrue(all(r["retirement_date"] == "" for r in rows))
                client.error.assert_called_once()
                self.assertEqual(client.error.call_args.args[:2],
                                 (retirements.SOURCE_URL, "download_retirement_schedule"))
                client.get.assert_not_called()

    def test_changed_title_layout_invalid_date_and_empty_source_fail_explicitly(self):
        sources = [
            "", "<h1>Access denied</h1>",
            schedule("| model-a | 001 | GA | 2026-04-02 | — |").replace(
                "Model retirement schedule", "Unrelated page"),
            "# Model retirement schedule\n\n### Azure OpenAI\n\nNo table",
            schedule("| model-a | 001 | GA | sometime next year | — |"),
            schedule("| model-a | 001 | GA | 2026-02-30 | — |"),
            schedule("| model-a | 001 | GA | — | — |").replace("Retirement date", "End date"),
            schedule("| model-a | 001 | GA | — |"),
        ]
        for source in sources:
            with self.subTest(source=source), patch.object(
                    retirements, "download_schedule", return_value=source):
                client = Mock()
                row = retirements.collect_retirements(client, [deployment()])[0]
                self.assertEqual(row["retirement_status"], "schedule_unavailable")
                client.error.assert_called_once()
                self.assertEqual(client.error.call_args.args[1], "parse_retirement_schedule")

    def test_custom_warning_window_and_utc_date(self):
        source = schedule("| model-a | 001 | GA | 2026-01-02 | — |")
        row = self.collect(source, [deployment()], warning_days=0)[0]
        self.assertEqual(row["retirement_status"], "scheduled")
        with patch.object(retirements, "download_schedule", return_value=source):
            row = retirements.collect_retirements(
                Mock(), [deployment()], now=datetime(
                    2026, 1, 2, 1, tzinfo=timezone(timedelta(hours=5))))[0]
        self.assertEqual(row["days_to_retirement"], 1)
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                retirements.collect_retirements(Mock(), [], warning_days=value)

    @patch.object(retirements, "build_opener")
    def test_downloader_is_fixed_bounded_public_request(self, build_opener):
        response = Mock()
        response.read.return_value = b"# Model retirement schedule"
        build_opener.return_value.open.return_value.__enter__.return_value = response
        self.assertEqual(retirements.download_schedule(), "# Model retirement schedule")
        request = build_opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, retirements.SOURCE_URL)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(build_opener.return_value.open.call_args.kwargs["timeout"], 20)
        response.read.assert_called_once_with(retirements.MAX_SOURCE_BYTES + 1)
        response.read.return_value = b"x" * (retirements.MAX_SOURCE_BYTES + 1)
        with self.assertRaises(ValueError):
            retirements.download_schedule()

    def test_redirects_are_not_followed_to_other_sources(self):
        with self.assertRaises(ValueError):
            retirements._NoRedirect().redirect_request(
                None, io.BytesIO(), 302, "", {}, "https://other.example/")


if __name__ == "__main__":
    unittest.main()
