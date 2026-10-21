# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import contextlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from scripts import check_ruleset_drift as drift

ROOT = Path(__file__).resolve().parents[1]
ORG = "hegemony-sh"


def example(rule_id=1):
    return {
        "id": rule_id,
        "name": "protect-main",
        "target": "branch",
        "source_type": "Organization",
        "source": ORG,
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": ["refs/heads/main", "refs/heads/develop"],
                "exclude": [],
            },
            "repository_name": {"include": ["~ALL"], "exclude": ["sandbox", "demo"]},
        },
        "rules": [
            {"type": "deletion"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "require_code_owner_review": True,
                    "allowed_merge_methods": ["merge", "squash"],
                },
            },
        ],
        "bypass_actors": [
            {
                "actor_type": "OrganizationAdmin",
                "actor_id": None,
                "bypass_mode": "always",
            },
            {
                "actor_type": "Integration",
                "actor_id": 123,
                "bypass_mode": "pull_request",
            },
        ],
    }


class ComparisonTests(unittest.TestCase):
    def test_actual_exports_ignore_api_metadata_and_set_order(self):
        recorded = drift.load_recorded(ROOT / "rulesets", ORG)
        live = deepcopy(recorded)
        for rule in live.values():
            rule.update(
                {
                    "node_id": "api-node",
                    "created_at": "today",
                    "updated_at": "tomorrow",
                    "_links": {"self": "api-url"},
                    "current_user_can_bypass": "always",
                }
            )
            rule["rules"].reverse()
            rule["conditions"]["repository_name"]["protected"] = False
            for item in rule["rules"]:
                item.get("parameters", {}).get("allowed_merge_methods", []).reverse()
        self.assertEqual([], drift.compare(recorded, live))

    def test_all_known_set_arrays_are_unordered(self):
        before = example()
        after = deepcopy(before)
        after["bypass_actors"].reverse()
        after["conditions"]["ref_name"]["include"].reverse()
        after["conditions"]["repository_name"]["exclude"].reverse()
        after["rules"][1]["parameters"]["allowed_merge_methods"].reverse()
        after["rules"].reverse()
        self.assertEqual([], drift.compare({1: before}, {1: after}))

    def test_policy_changes_produce_diffs(self):
        changes = {
            "enforcement": lambda r: r.update(enforcement="disabled"),
            "repository scope": lambda r: r["conditions"]["repository_name"].update(
                include=["one-repo"]
            ),
            "repository exclusion": lambda r: r["conditions"]["repository_name"][
                "exclude"
            ].append("hegemony"),
            "ref scope": lambda r: r["conditions"]["ref_name"].update(
                include=["refs/heads/other"]
            ),
            "rename protection": lambda r: r["conditions"]["repository_name"].update(
                protected=True
            ),
            "code owner review": lambda r: r["rules"][1]["parameters"].update(
                require_code_owner_review=False
            ),
            "approval count": lambda r: r["rules"][1]["parameters"].update(
                required_approving_review_count=0
            ),
            "bypass removal": lambda r: r.update(bypass_actors=[]),
            "bypass mode": lambda r: r["bypass_actors"][0].update(bypass_mode="exempt"),
            "new policy field": lambda r: r.update(future_policy={"enabled": True}),
            "rule removal": lambda r: r["rules"].pop(0),
        }
        for label, change in changes.items():
            with self.subTest(label=label):
                before = example()
                after = deepcopy(before)
                change(after)
                diffs = drift.compare({1: before}, {1: after})
                self.assertEqual(1, len(diffs))
                self.assertIn("Changed ruleset 1", diffs[0])
                self.assertIn("--- recorded/1", diffs[0])
                self.assertIn("+++ live/1", diffs[0])

    def test_untracked_and_deleted_rulesets(self):
        diffs = drift.compare({1: example(1)}, {2: example(2)})
        self.assertEqual(2, len(diffs))
        self.assertIn("Missing live ruleset 1", diffs[0])
        self.assertIn("Untracked live ruleset 2", diffs[1])

    def test_unknown_array_order_and_nested_metadata_are_not_discarded(self):
        before = example()
        before["future_policy"] = {"node_id": "policy-value", "ordered": [1, 2]}
        after = deepcopy(before)
        after["future_policy"]["ordered"].reverse()
        self.assertTrue(drift.compare({1: before}, {1: after}))
        after = deepcopy(before)
        after["future_policy"]["node_id"] = "different"
        self.assertTrue(drift.compare({1: before}, {1: after}))


class ValidationTests(unittest.TestCase):
    def test_rejects_incomplete_scope_and_hidden_bypasses(self):
        for field in ("repository_name", "bypass_actors"):
            with self.subTest(field=field):
                rule = example()
                if field == "repository_name":
                    del rule["conditions"][field]
                else:
                    del rule[field]
                with self.assertRaises(drift.CheckError):
                    drift.validate_rule(rule, ORG, "fixture")

    def test_rejects_wrong_owner_and_boolean_id(self):
        for updates in (
            {"source": "other-org"},
            {"source": None},
            {"source_type": "Repository"},
            {"id": True},
        ):
            with self.subTest(updates=updates):
                rule = example()
                rule.update(updates)
                with self.assertRaises(drift.CheckError):
                    drift.validate_rule(rule, ORG, "fixture")

    def test_rejects_malformed_policy_shapes(self):
        for field in ("target", "enforcement"):
            with self.subTest(field=field):
                rule = example()
                rule[field] = []
                with self.assertRaises(drift.CheckError):
                    drift.validate_rule(rule, ORG, "fixture")
        for selector in (None, {}, []):
            with self.subTest(selector=selector):
                rule = example()
                rule["conditions"]["repository_name"] = selector
                with self.assertRaises(drift.CheckError):
                    drift.validate_rule(rule, ORG, "fixture")

    def test_rejects_empty_directory_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with self.assertRaisesRegex(drift.CheckError, "No ruleset"):
                drift.load_recorded(directory, ORG)
            for filename in ("one.json", "two.json"):
                (directory / filename).write_text(json.dumps(example()))
            with self.assertRaisesRegex(drift.CheckError, "Duplicate recorded"):
                drift.load_recorded(directory, ORG)

    def test_rejects_malformed_json_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for text in ('{"id":', '{"id": 1, "id": 2}'):
                with self.subTest(text=text):
                    (directory / "one.json").write_text(text)
                    with self.assertRaises(drift.CheckError):
                        drift.load_recorded(directory, ORG)


class ApiTests(unittest.TestCase):
    def test_inventory_pagination_includes_untracked_rules(self):
        prefix = f"/orgs/{ORG}/rulesets"

        def response(endpoint):
            if endpoint == prefix + "?per_page=100&page=1":
                return [{"id": n} for n in range(1, 101)]
            if endpoint == prefix + "?per_page=100&page=2":
                return [{"id": 101}]
            return example(int(endpoint.rsplit("/", 1)[1]))

        client = Mock()
        client.get.side_effect = response
        result = drift.fetch_live(client, ORG)
        self.assertEqual(set(range(1, 102)), set(result))
        self.assertEqual(103, client.get.call_count)

    def test_missing_bypass_visibility_is_an_error(self):
        rule = example()
        del rule["bypass_actors"]
        client = Mock()
        client.get.side_effect = [[{"id": 1}], rule]
        with self.assertRaisesRegex(drift.CheckError, "bypass"):
            drift.fetch_live(client, ORG)

    def test_invalid_inventories_and_wrong_detail_id(self):
        for inventory in (
            {"message": "denied"},
            [{"id": True}],
            [{"id": 1}, {"id": 1}],
        ):
            with self.subTest(inventory=inventory):
                client = Mock()
                client.get.return_value = inventory
                with self.assertRaises(drift.CheckError):
                    drift.fetch_live(client, ORG)
        client = Mock()
        client.get.side_effect = [[{"id": 1}], example(2)]
        with self.assertRaisesRegex(drift.CheckError, "wrong definition"):
            drift.fetch_live(client, ORG)

    def test_http_requests_are_get_only_and_use_organization_endpoint(self):
        client = drift.GitHub("secret-value")
        client.opener = Mock()
        client.opener.open.return_value = io.BytesIO(b"[]")
        self.assertEqual([], client.get(f"/orgs/{ORG}/rulesets?per_page=100&page=1"))
        request = client.opener.open.call_args.args[0]
        self.assertEqual("GET", request.get_method())
        self.assertEqual(
            "https://api.github.com/orgs/hegemony-sh/rulesets?per_page=100&page=1",
            request.full_url,
        )
        self.assertEqual("Bearer secret-value", request.get_header("Authorization"))
        self.assertIsNone(request.data)
        self.assertEqual(30, client.opener.open.call_args.kwargs["timeout"])

    def test_http_and_network_errors_do_not_leak_response_contents(self):
        for error in (
            HTTPError(
                "https://api.github.com",
                403,
                "secret-value",
                {},
                io.BytesIO(b"secret-value"),
            ),
            URLError("secret-value"),
            TimeoutError("secret-value"),
        ):
            with self.subTest(error=type(error)):
                client = drift.GitHub("secret-value")
                client.opener = Mock()
                client.opener.open.side_effect = error
                with self.assertRaises(drift.CheckError) as caught:
                    client.get(f"/orgs/{ORG}/rulesets")
                self.assertNotIn("secret-value", str(caught.exception))

    def test_invalid_json_response_is_a_check_error(self):
        client = drift.GitHub("secret-value")
        client.opener = Mock()
        client.opener.open.return_value = io.BytesIO(b"<html>gateway error</html>")
        with self.assertRaisesRegex(drift.CheckError, "invalid JSON"):
            client.get(f"/orgs/{ORG}/rulesets")

    def test_redirects_do_not_forward_credentials(self):
        self.assertIsNone(
            drift.NoRedirect().redirect_request(
                None, None, 302, "moved", {}, "https://other.example"
            )
        )


class CommandTests(unittest.TestCase):
    def run_check(self, extra_args=(), environment=None):
        output = io.StringIO()
        with (
            patch.dict(os.environ, environment or {}, clear=True),
            contextlib.redirect_stdout(output),
        ):
            status = drift.main(["--rules-dir", str(ROOT / "rulesets"), *extra_args])
        return status, output.getvalue()

    def test_offline_validation_uses_no_api_or_token(self):
        with patch.object(drift, "GitHub") as client:
            status, output = self.run_check(["--validate-only"])
        self.assertEqual(0, status)
        self.assertIn("live drift was not checked", output)
        client.assert_not_called()

    def test_missing_secret_is_not_a_successful_drift_check(self):
        status, output = self.run_check()
        self.assertEqual(2, status)
        self.assertIn("ORG_RULESETS_TOKEN is missing", output)
        self.assertNotIn("OK:", output)

    def test_success_drift_and_api_failure_exit_codes_and_summaries(self):
        recorded = drift.load_recorded(ROOT / "rulesets", ORG)
        modified = deepcopy(recorded)
        next(iter(modified.values()))["enforcement"] = "disabled"
        for live, expected, marker in (
            (recorded, 0, "OK:"),
            (modified, 1, "DRIFT:"),
            (drift.CheckError("Access denied"), 2, "ERROR:"),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                summary = Path(tmp) / "summary.md"
                with patch.object(drift, "fetch_live") as fetch:
                    if isinstance(live, Exception):
                        fetch.side_effect = live
                    else:
                        fetch.return_value = live
                    status, output = self.run_check(
                        environment={
                            "ORG_RULESETS_TOKEN": "test",
                            "GITHUB_STEP_SUMMARY": str(summary),
                        }
                    )
                self.assertEqual(expected, status)
                self.assertIn(marker, output)
                self.assertIn(marker, summary.read_text())
                self.assertIn("Organization ruleset drift", summary.read_text())

    def test_summary_fences_and_log_indentation_contain_data(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            summary = Path(tmp) / "summary.md"
            drift.report("```\n::error::data, not a workflow command", str(summary))
            self.assertIn("````text", summary.read_text())
            self.assertIn("\n  ::error::", output.getvalue())


if __name__ == "__main__":
    unittest.main()
