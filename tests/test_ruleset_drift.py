# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``scripts/check_ruleset_drift.py``.

The checker and this file are kept byte-identical in the organisation's
``.github`` repository and in the platform repository, so the tests work out
which scope the checkout records from the recorded rulesets next to the
checker: the organisation's under ``rulesets/``, or one repository's own
under ``.github/rulesets/``. Everything else runs on fixtures; no test
reaches GitHub.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from copy import deepcopy
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from scripts import check_ruleset_drift as drift

ROOT = Path(drift.__file__).resolve().parents[1]
ORG = drift.Scope("hegemony-sh")
REPO = drift.Scope("hegemony-sh", "hegemony")


def recorded_scope() -> tuple[drift.Scope, Path]:
    """The scope this checkout records, read from its first recorded ruleset."""
    for directory in (ROOT / "rulesets", ROOT / ".github" / "rulesets"):
        files = sorted(directory.glob("*.json"))
        if files:
            rule = json.loads(files[0].read_text(encoding="utf-8"))
            organization = rule["source_type"] == "Organization"
            scope = drift.Scope.parse(
                rule["source"] if organization else None,
                None if organization else rule["source"],
            )
            return scope, directory
    raise AssertionError("no recorded rulesets next to the checker")


SCOPE, RULES_DIR = recorded_scope()
SCOPE_ARGS = ["--repo", SCOPE.source] if SCOPE.is_repository else ["--org", SCOPE.source]


def example(rule_id: int | None = 1, scope: drift.Scope = ORG, name: str = "protect-main") -> dict:
    """A complete export of one ruleset, in the shape the API returns."""
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "target": "branch",
        "source_type": scope.source_type,
        "source": scope.source,
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": ["refs/heads/main", "refs/heads/develop"],
                "exclude": [],
            },
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
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [{"context": "CI"}, {"context": "DCO"}],
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
    if rule_id is None:
        del rule["id"]
    if not scope.is_repository:
        rule["conditions"]["repository_name"] = {
            "include": ["~ALL"],
            "exclude": ["sandbox", "demo"],
        }
    return rule


def recorded(*rules: dict) -> dict[Path, dict]:
    """Recorded rulesets as ``load_recorded`` returns them, one file per rule."""
    return {Path(f"rule-{index}.json"): rule for index, rule in enumerate(rules, start=1)}


class ScopeTests(unittest.TestCase):
    def test_exactly_one_scope_argument(self) -> None:
        for org, repo in ((None, None), ("hegemony-sh", "hegemony-sh/hegemony")):
            with (
                self.subTest(org=org, repo=repo),
                self.assertRaisesRegex(drift.CheckError, "exactly one"),
            ):
                drift.Scope.parse(org, repo)

    def test_rejects_malformed_names(self) -> None:
        for org, repo in (
            ("", None),
            ("-dash", None),
            ("owner/name", None),
            (None, "no-slash"),
            (None, "owner/"),
            (None, "/name"),
            (None, "owner/na me"),
            (None, "owner/../name"),
        ):
            with self.subTest(org=org, repo=repo), self.assertRaises(drift.CheckError):
                drift.Scope.parse(org, repo)

    def test_repository_scope(self) -> None:
        scope = drift.Scope.parse(None, "hegemony-sh/hegemony")
        self.assertEqual(REPO, scope)
        self.assertTrue(scope.is_repository)
        self.assertEqual("repository", scope.label)
        self.assertEqual("Repository", scope.source_type)
        self.assertEqual("hegemony-sh/hegemony", scope.source)
        self.assertEqual("/repos/hegemony-sh/hegemony/rulesets", scope.endpoint)
        self.assertEqual(
            "/repos/hegemony-sh/hegemony/rulesets?includes_parents=false&per_page=100&page=2",
            scope.inventory_endpoint(2),
        )
        self.assertEqual("REPO_RULESETS_TOKEN", scope.token_variable)
        self.assertEqual(Path("/x/.github/rulesets"), scope.default_rules_dir(Path("/x")))

    def test_organization_scope(self) -> None:
        scope = drift.Scope.parse("hegemony-sh", None)
        self.assertEqual(ORG, scope)
        self.assertFalse(scope.is_repository)
        self.assertEqual("organization", scope.label)
        self.assertEqual("Organization", scope.source_type)
        self.assertEqual("hegemony-sh", scope.source)
        self.assertEqual("/orgs/hegemony-sh/rulesets", scope.endpoint)
        self.assertEqual(
            "/orgs/hegemony-sh/rulesets?per_page=100&page=1", scope.inventory_endpoint(1)
        )
        self.assertEqual("ORG_RULESETS_TOKEN", scope.token_variable)
        self.assertEqual(Path("/x/rulesets"), scope.default_rules_dir(Path("/x")))


class ComparisonTests(unittest.TestCase):
    def test_actual_exports_ignore_api_metadata_and_set_order(self) -> None:
        files = drift.load_recorded(RULES_DIR, SCOPE)
        live = {}
        for index, rule in enumerate(files.values(), start=1):
            item = deepcopy(rule)
            item.setdefault("id", 1000 + index)
            item.update(
                {
                    "node_id": "api-node",
                    "created_at": "today",
                    "updated_at": "tomorrow",
                    "_links": {"self": "api-url"},
                    "current_user_can_bypass": "always",
                }
            )
            item["rules"].reverse()
            if "repository_name" in item["conditions"]:
                item["conditions"]["repository_name"]["protected"] = False
            for entry in item["rules"]:
                parameters = entry.get("parameters", {})
                for key in drift.UNORDERED_PARAMETERS:
                    if isinstance(parameters.get(key), list):
                        parameters[key].reverse()
            live[item["id"]] = item
        differences = drift.compare(files, live)
        # A file recorded before GitHub assigned its id is matched by name and
        # asks for the id to be recorded; nothing else may differ.
        unrecorded = [rule for rule in files.values() if "id" not in rule]
        self.assertEqual(len(unrecorded), len(differences))
        for difference in differences:
            self.assertIn("Unrecorded ruleset id", difference)

    def test_all_known_set_arrays_are_unordered(self) -> None:
        for scope in (ORG, REPO):
            with self.subTest(scope=scope.label):
                before = example(scope=scope)
                after = deepcopy(before)
                after["bypass_actors"].reverse()
                after["conditions"]["ref_name"]["include"].reverse()
                if "repository_name" in after["conditions"]:
                    after["conditions"]["repository_name"]["exclude"].reverse()
                after["rules"][1]["parameters"]["allowed_merge_methods"].reverse()
                after["rules"][2]["parameters"]["required_status_checks"].reverse()
                after["rules"].reverse()
                self.assertEqual([], drift.compare(recorded(before), {1: after}))

    def test_policy_changes_produce_diffs(self) -> None:
        changes = {
            "enforcement": lambda r: r.update(enforcement="disabled"),
            "repository scope": lambda r: r["conditions"]["repository_name"].update(
                include=["one-repo"]
            ),
            "repository exclusion": lambda r: r["conditions"]["repository_name"]["exclude"].append(
                "x"
            ),
            "ref scope": lambda r: r["conditions"]["ref_name"].update(include=["refs/heads/other"]),
            "rename protection": lambda r: r["conditions"]["repository_name"].update(
                protected=True
            ),
            "code owner review": lambda r: r["rules"][1]["parameters"].update(
                require_code_owner_review=False
            ),
            "approval count": lambda r: r["rules"][1]["parameters"].update(
                required_approving_review_count=0
            ),
            "required check": lambda r: r["rules"][2]["parameters"]["required_status_checks"].pop(),
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
                diffs = drift.compare(recorded(before), {1: after})
                self.assertEqual(1, len(diffs))
                self.assertIn('Changed ruleset 1 ("protect-main")', diffs[0])
                self.assertIn("--- recorded/1", diffs[0])
                self.assertIn("+++ live/1", diffs[0])

    def test_untracked_and_deleted_rulesets(self) -> None:
        diffs = drift.compare(recorded(example(1)), {2: example(2)})
        self.assertEqual(2, len(diffs))
        self.assertIn("Missing live ruleset 1", diffs[0])
        self.assertIn("Untracked live ruleset 2", diffs[1])

    def test_unknown_array_order_and_nested_metadata_are_not_discarded(self) -> None:
        before = example()
        before["future_policy"] = {"node_id": "policy-value", "ordered": [1, 2]}
        after = deepcopy(before)
        after["future_policy"]["ordered"].reverse()
        self.assertTrue(drift.compare(recorded(before), {1: after}))
        after = deepcopy(before)
        after["future_policy"]["node_id"] = "different"
        self.assertTrue(drift.compare(recorded(before), {1: after}))

    def test_file_without_id_is_matched_by_name_once_and_asks_for_the_id(self) -> None:
        files = {Path("main.json"): example(None)}
        diffs = drift.compare(files, {7: example(7)})
        self.assertEqual(1, len(diffs))
        self.assertIn('Unrecorded ruleset id 7 ("protect-main"): main.json', diffs[0])
        self.assertIn('add "id": 7 to the file', diffs[0])

        changed = example(7)
        changed["enforcement"] = "evaluate"
        diffs = drift.compare(files, {7: changed})
        self.assertEqual(2, len(diffs))
        self.assertIn("Changed ruleset 7", diffs[0])
        self.assertIn("Unrecorded ruleset id 7", diffs[1])

        diffs = drift.compare(files, {7: example(7, name="other")})
        self.assertEqual(2, len(diffs))
        self.assertIn('Missing live ruleset main.json ("protect-main")', diffs[0])
        self.assertIn("Untracked live ruleset 7", diffs[1])

        with self.assertRaisesRegex(drift.CheckError, "record the id"):
            drift.compare(files, {7: example(7), 8: example(8)})

    def test_name_matching_never_takes_a_ruleset_recorded_by_id(self) -> None:
        files = {Path("by-id.json"): example(7), Path("by-name.json"): example(None)}
        diffs = drift.compare(files, {7: example(7)})
        self.assertEqual(1, len(diffs))
        self.assertIn('Missing live ruleset by-name.json ("protect-main")', diffs[0])


class ValidationTests(unittest.TestCase):
    def test_rejects_incomplete_scope_and_hidden_bypasses(self) -> None:
        for field in ("repository_name", "bypass_actors"):
            with self.subTest(field=field):
                rule = example()
                if field == "repository_name":
                    del rule["conditions"][field]
                else:
                    del rule[field]
                with self.assertRaises(drift.CheckError):
                    drift.validate_rule(rule, ORG, "fixture")
        rule = example(scope=REPO)
        rule["conditions"]["repository_name"] = {"include": ["~ALL"], "exclude": []}
        with self.assertRaisesRegex(drift.CheckError, "no repository selector"):
            drift.validate_rule(rule, REPO, "fixture")

    def test_rejects_wrong_owner_and_boolean_id(self) -> None:
        for scope in (ORG, REPO):
            for updates in (
                {"source": "other-org"},
                {"source": None},
                {"source_type": "Enterprise"},
                {"source_type": "Repository" if scope is ORG else "Organization"},
                {"id": True},
                {"id": 0},
                {"id": "7"},
            ):
                with self.subTest(scope=scope.label, updates=updates):
                    rule = example(scope=scope)
                    rule.update(updates)
                    with self.assertRaises(drift.CheckError):
                        drift.validate_rule(rule, scope, "fixture")

    def test_source_matches_case_insensitively_and_id_is_optional(self) -> None:
        rule = example(None)
        rule["source"] = "Hegemony-SH"
        drift.validate_rule(rule, ORG, "fixture")
        rule = example(None, scope=REPO)
        rule["source"] = "Hegemony-SH/Hegemony"
        drift.validate_rule(rule, REPO, "fixture")

    def test_rejects_malformed_policy_shapes(self) -> None:
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
        # Subtest parameters cross an xdist worker boundary, so they are labels,
        # never the lambdas or exceptions themselves.
        changes = {
            "empty name": lambda r: r.update(name=""),
            "unknown target": lambda r: r.update(target="commit"),
            "unknown enforcement": lambda r: r.update(enforcement="on"),
            "conditions not an object": lambda r: r.update(conditions=[]),
            "no ref_name": lambda r: r["conditions"].pop("ref_name"),
            "rules not an array": lambda r: r.update(rules={}),
            "bypass_actors not an array": lambda r: r.update(bypass_actors=None),
        }
        for label, change in changes.items():
            with self.subTest(label=label):
                rule = example()
                change(rule)
                with self.assertRaises(drift.CheckError):
                    drift.validate_rule(rule, ORG, "fixture")

    def test_rejects_empty_directory_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with self.assertRaisesRegex(drift.CheckError, "No ruleset"):
                drift.load_recorded(directory, ORG)
            for filename in ("one.json", "two.json"):
                (directory / filename).write_text(json.dumps(example()), encoding="utf-8")
            with self.assertRaisesRegex(drift.CheckError, "Duplicate recorded ruleset ID"):
                drift.load_recorded(directory, ORG)
            for filename in ("one.json", "two.json"):
                (directory / filename).write_text(json.dumps(example(None)), encoding="utf-8")
            with self.assertRaisesRegex(drift.CheckError, "Duplicate recorded ruleset name"):
                drift.load_recorded(directory, ORG)

    def test_rejects_malformed_json_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for text in ('{"id":', '{"id": 1, "id": 2}', "[]"):
                with self.subTest(text=text):
                    (directory / "one.json").write_text(text, encoding="utf-8")
                    with self.assertRaises(drift.CheckError):
                        drift.load_recorded(directory, ORG)


class ApiTests(unittest.TestCase):
    def test_inventory_pagination_includes_untracked_rules(self) -> None:
        prefix = f"/orgs/{ORG.owner}/rulesets"

        def response(endpoint: str, token_variable: str) -> object:
            self.assertEqual("ORG_RULESETS_TOKEN", token_variable)
            if endpoint == prefix + "?per_page=100&page=1":
                return [{"id": n, "source_type": "Organization"} for n in range(1, 101)]
            if endpoint == prefix + "?per_page=100&page=2":
                return [{"id": 101, "source_type": "Organization"}]
            return example(int(endpoint.rsplit("/", 1)[1]))

        client = Mock()
        client.get.side_effect = response
        result = drift.fetch_live(client, ORG)
        self.assertEqual(set(range(1, 102)), set(result))
        self.assertEqual(103, client.get.call_count)

    def test_repository_inventory_skips_inherited_rulesets(self) -> None:
        client = Mock()
        client.get.side_effect = [
            [
                {"id": 1, "source_type": "Repository", "source": REPO.source},
                {"id": 2, "source_type": "Organization", "source": REPO.owner},
            ],
            example(1, scope=REPO),
        ]
        self.assertEqual([1], list(drift.fetch_live(client, REPO)))
        self.assertEqual(2, client.get.call_count)
        self.assertEqual(
            "/repos/hegemony-sh/hegemony/rulesets?includes_parents=false&per_page=100&page=1",
            client.get.call_args_list[0].args[0],
        )
        self.assertEqual(
            "/repos/hegemony-sh/hegemony/rulesets/1", client.get.call_args_list[1].args[0]
        )

    def test_missing_bypass_visibility_is_an_error(self) -> None:
        rule = example()
        del rule["bypass_actors"]
        client = Mock()
        client.get.side_effect = [[{"id": 1}], rule]
        with self.assertRaisesRegex(drift.CheckError, "bypass"):
            drift.fetch_live(client, ORG)

    def test_invalid_inventories_and_wrong_detail_id(self) -> None:
        for inventory in (
            {"message": "denied"},
            [{"id": True}],
            [{"id": 1}, {"id": 1}],
            ["1"],
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

    def test_http_requests_are_get_only_and_use_the_scope_endpoint(self) -> None:
        opener = Mock()
        client = drift.GitHub("secret-value", opener=opener)
        opener.open.return_value = io.BytesIO(b"[]")
        self.assertEqual([], client.get(REPO.inventory_endpoint(1), REPO.token_variable))
        request = opener.open.call_args.args[0]
        self.assertEqual("GET", request.get_method())
        self.assertEqual(
            "https://api.github.com/repos/hegemony-sh/hegemony/rulesets"
            "?includes_parents=false&per_page=100&page=1",
            request.full_url,
        )
        self.assertEqual("Bearer secret-value", request.get_header("Authorization"))
        self.assertEqual(drift.API_VERSION, request.get_header("X-github-api-version"))
        self.assertIsNone(request.data)
        self.assertEqual(30, opener.open.call_args.kwargs["timeout"])

    def test_http_and_network_errors_do_not_leak_response_contents(self) -> None:
        errors = {
            "HTTP 403": HTTPError(
                "https://api.github.com",
                403,
                "secret-value",
                Message(),
                io.BytesIO(b"secret-value"),
            ),
            "HTTP 500": HTTPError(
                "https://api.github.com",
                500,
                "secret-value",
                Message(),
                io.BytesIO(b"secret-value"),
            ),
            "URLError": URLError("secret-value"),
            "TimeoutError": TimeoutError("secret-value"),
        }
        for label, error in errors.items():
            with self.subTest(label=label):
                opener = Mock()
                client = drift.GitHub("secret-value", opener=opener)
                opener.open.side_effect = error
                with self.assertRaises(drift.CheckError) as caught:
                    client.get(ORG.endpoint, ORG.token_variable)
                self.assertNotIn("secret-value", str(caught.exception))
                if isinstance(error, HTTPError):
                    self.assertIn(f"HTTP {error.code}", str(caught.exception))
                    self.assertEqual(
                        error.code == 403, "ORG_RULESETS_TOKEN" in str(caught.exception)
                    )

    def test_invalid_json_response_is_a_check_error(self) -> None:
        opener = Mock()
        client = drift.GitHub("secret-value", opener=opener)
        opener.open.return_value = io.BytesIO(b"<html>gateway error</html>")
        with self.assertRaisesRegex(drift.CheckError, "invalid JSON"):
            client.get(ORG.endpoint, ORG.token_variable)

    def test_redirects_do_not_forward_credentials(self) -> None:
        self.assertIsNone(
            drift.NoRedirect().redirect_request(
                None, None, 302, "moved", {}, "https://other.example"
            )
        )


class CommandTests(unittest.TestCase):
    def run_check(
        self,
        extra_args: tuple[str, ...] | list[str] = (),
        environment: dict[str, str] | None = None,
        rules_dir: Path = RULES_DIR,
        scope_args: list[str] = SCOPE_ARGS,
    ) -> tuple[int, str]:
        output = io.StringIO()
        with (
            patch.dict(os.environ, environment or {}, clear=True),
            contextlib.redirect_stdout(output),
        ):
            status = drift.main(["--rules-dir", str(rules_dir), *scope_args, *extra_args])
        return status, output.getvalue()

    def write_fixtures(self, directory: Path, *rules: dict) -> None:
        for index, rule in enumerate(rules, start=1):
            (directory / f"rule-{index}.json").write_text(json.dumps(rule), encoding="utf-8")

    def test_offline_validation_uses_no_api_or_token(self) -> None:
        with patch.object(drift, "GitHub") as client:
            status, output = self.run_check(["--validate-only"])
        self.assertEqual(0, status)
        self.assertIn("live drift was not checked", output)
        client.assert_not_called()

    def test_scope_argument_is_required_and_exclusive(self) -> None:
        for scope_args in ([], ["--org", "hegemony-sh", "--repo", "hegemony-sh/hegemony"]):
            with self.subTest(scope_args=scope_args):
                status, output = self.run_check(["--validate-only"], scope_args=scope_args)
                self.assertEqual(2, status)
                self.assertIn("ERROR: drift could not be checked. Give exactly one of", output)
        status, output = self.run_check(["--validate-only", "--export"])
        self.assertEqual(2, status)
        self.assertIn("exclude each other", output)

    def test_missing_secret_is_not_a_successful_drift_check(self) -> None:
        status, output = self.run_check()
        self.assertEqual(2, status)
        self.assertIn(f"{SCOPE.token_variable} is missing", output)
        self.assertNotIn("OK:", output)

    def test_success_drift_and_api_failure_exit_codes_and_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.write_fixtures(directory, example(1, SCOPE), example(2, SCOPE, name="second"))
            files = drift.load_recorded(directory, SCOPE)
            live = {rule["id"]: deepcopy(rule) for rule in files.values()}
            modified = deepcopy(live)
            modified[1]["enforcement"] = "disabled"
            for fetched, expected, marker in (
                (live, 0, "OK: all 2"),
                (modified, 1, "DRIFT: 1"),
                (drift.CheckError("Access denied"), 2, "ERROR:"),
            ):
                with self.subTest(expected=expected):
                    summary = directory / "summary.md"
                    summary.unlink(missing_ok=True)
                    with patch.object(drift, "fetch_live") as fetch:
                        if isinstance(fetched, Exception):
                            fetch.side_effect = fetched
                        else:
                            fetch.return_value = fetched
                        status, output = self.run_check(
                            environment={
                                SCOPE.token_variable: "test",
                                "GITHUB_STEP_SUMMARY": str(summary),
                            },
                            rules_dir=directory,
                        )
                    fetch.assert_called_once()
                    self.assertEqual("test", fetch.call_args.args[0].token)
                    self.assertEqual(SCOPE, fetch.call_args.args[1])
                    self.assertEqual(expected, status)
                    self.assertIn(marker, output)
                    self.assertIn(marker, summary.read_text(encoding="utf-8"))
                    self.assertIn("## Ruleset drift", summary.read_text(encoding="utf-8"))

    def test_export_records_live_rulesets_and_their_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "main.json").write_text(json.dumps(example(None, SCOPE)), encoding="utf-8")
            live = {
                7: {
                    **example(7, SCOPE),
                    "node_id": "api-node",
                    "_links": {},
                    "updated_at": "today",
                },
                8: example(8, SCOPE, name="Release tags / v*"),
            }
            with patch.object(drift, "fetch_live", return_value=live):
                status, output = self.run_check(
                    ["--export"], environment={SCOPE.token_variable: "test"}, rules_dir=directory
                )
            self.assertEqual(0, status)
            self.assertIn("Exported 2 live", output)
            self.assertIn("main.json, Release-tags-v.json", output)
            text = (directory / "main.json").read_text(encoding="utf-8")
            self.assertTrue(text.startswith('{\n  "id": 7,\n  "name": "protect-main",\n'))
            self.assertTrue(text.endswith("}\n"))
            self.assertNotIn("node_id", text)
            self.assertEqual(
                8, json.loads((directory / "Release-tags-v.json").read_text(encoding="utf-8"))["id"]
            )
            # The export is a complete recording: the next check matches.
            status, output = self.run_check(["--validate-only"], rules_dir=directory)
            self.assertEqual(0, status)
            self.assertNotIn("carry no id", output)
            with patch.object(drift, "fetch_live", return_value=live):
                status, output = self.run_check(
                    environment={SCOPE.token_variable: "test"}, rules_dir=directory
                )
            self.assertEqual(0, status)
            self.assertIn("OK: all 2", output)

    def test_export_keeps_stale_files_and_fills_an_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch.object(drift, "fetch_live", return_value={7: example(7, SCOPE)}):
                status, output = self.run_check(
                    ["--export"], environment={SCOPE.token_variable: "test"}, rules_dir=directory
                )
            self.assertEqual(0, status)
            self.assertEqual(["protect-main.json"], [path.name for path in directory.iterdir()])
            self.write_fixtures(directory, example(9, SCOPE, name="gone"))
            with patch.object(drift, "fetch_live", return_value={7: example(7, SCOPE)}):
                status, output = self.run_check(
                    ["--export"], environment={SCOPE.token_variable: "test"}, rules_dir=directory
                )
            self.assertEqual(0, status)
            self.assertIn("no longer live (left as they are): rule-1.json", output)
            self.assertEqual(
                9, json.loads((directory / "rule-1.json").read_text(encoding="utf-8"))["id"]
            )

    def test_summary_fences_and_log_indentation_contain_data(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            summary = Path(tmp) / "summary.md"
            drift.report("```\n::error::data, not a workflow command", str(summary))
            self.assertIn("````text", summary.read_text(encoding="utf-8"))
            self.assertIn("\n  ::error::", output.getvalue())


if __name__ == "__main__":
    unittest.main()
