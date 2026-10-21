#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Compare committed organization rulesets with GitHub using GET requests only."""

from __future__ import annotations

import argparse
import difflib
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
RESPONSE_METADATA = {
    "_links",
    "node_id",
    "created_at",
    "updated_at",
    "current_user_can_bypass",
}
REPOSITORY_SELECTORS = {"repository_name", "repository_id", "repository_property"}
UNORDERED_PARAMETERS = {
    "allowed_merge_methods",
    "required_status_checks",
    "required_reviewers",
    "required_deployment_environments",
    "workflows",
}


class CheckError(Exception):
    """The check could not establish whether the live policy matches."""


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CheckError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_rule(rule, organization, label):
    if not isinstance(rule, dict):
        raise CheckError(f"{label}: expected a ruleset object")
    required = {
        "id",
        "name",
        "target",
        "source_type",
        "source",
        "enforcement",
        "conditions",
        "rules",
        "bypass_actors",
    }
    missing = required - rule.keys()
    if missing:
        raise CheckError(
            f"{label}: missing fields {', '.join(sorted(missing))}; a full organization export with bypass visibility is required"
        )
    if type(rule["id"]) is not int or rule["id"] <= 0:
        raise CheckError(f"{label}: id must be a positive integer")
    if (
        rule["source_type"] != "Organization"
        or not isinstance(rule["source"], str)
        or rule["source"].lower() != organization.lower()
    ):
        raise CheckError(
            f"{label}: expected an organization ruleset belonging to {organization}"
        )
    if not isinstance(rule["name"], str) or not rule["name"]:
        raise CheckError(f"{label}: name must be a nonempty string")
    if not isinstance(rule["target"], str) or rule["target"] not in {
        "branch",
        "tag",
        "push",
        "repository",
    }:
        raise CheckError(f"{label}: unsupported ruleset target")
    if not isinstance(rule["enforcement"], str) or rule["enforcement"] not in {
        "active",
        "disabled",
        "evaluate",
    }:
        raise CheckError(f"{label}: unsupported enforcement value")
    conditions = rule["conditions"]
    if (
        not isinstance(conditions, dict)
        or len(REPOSITORY_SELECTORS & conditions.keys()) != 1
    ):
        raise CheckError(
            f"{label}: exactly one organization repository selector is required"
        )
    selector = next(iter(REPOSITORY_SELECTORS & conditions.keys()))
    if not isinstance(conditions[selector], dict) or not conditions[selector]:
        raise CheckError(f"{label}: repository selector must be a nonempty object")
    if rule["target"] in {"branch", "tag"} and not isinstance(
        conditions.get("ref_name"), dict
    ):
        raise CheckError(f"{label}: branch/tag rulesets need ref_name conditions")
    if not isinstance(rule["rules"], list) or not isinstance(
        rule["bypass_actors"], list
    ):
        raise CheckError(f"{label}: rules and bypass_actors must be arrays")


def load_recorded(directory, organization):
    result = {}
    for path in sorted(directory.glob("*.json")):
        try:
            rule = json.loads(path.read_text(), object_pairs_hook=unique_keys)
        except (OSError, ValueError) as error:
            raise CheckError(f"Cannot read {path}: {error}") from error
        validate_rule(rule, organization, str(path))
        rule_id = rule["id"]
        if rule_id in result:
            raise CheckError(f"Duplicate recorded ruleset ID: {rule_id}")
        result[rule_id] = rule
    if not result:
        raise CheckError(f"No ruleset JSON files found in {directory}")
    return result


def canonicalize(value, path=()):
    """Ignore response metadata and ordering only for known set-valued arrays."""
    if isinstance(value, dict):
        values = dict(value)
        if not path:
            values = {
                key: item
                for key, item in values.items()
                if key not in RESPONSE_METADATA
            }
        if path == ("conditions", "repository_name"):
            # The UI export may omit this optional false-valued API setting.
            values.setdefault("protected", False)
        return {
            key: canonicalize(item, path + (key,))
            for key, item in sorted(values.items())
        }
    if isinstance(value, list):
        values = [canonicalize(item, path + ("*",)) for item in value]
        unordered = (
            path in {("rules",), ("bypass_actors",)}
            or (
                path[:1] == ("conditions",)
                and path[-1] in {"include", "exclude", "repository_ids"}
            )
            or (
                path[:3] == ("rules", "*", "parameters")
                and path[-1] in UNORDERED_PARAMETERS
            )
        )
        if unordered:
            values.sort(key=lambda item: json.dumps(item, sort_keys=True))
        return values
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the organization credential to a redirected URL.
        return None


class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = build_opener(NoRedirect())

    def get(self, endpoint):
        request = Request(
            API_ROOT + endpoint,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "hegemony-org-ruleset-drift",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response, object_pairs_hook=unique_keys)
        except HTTPError as error:
            # Do not print response bodies or request headers containing credentials.
            hint = ""
            if error.code in {401, 403, 404}:
                hint = " Verify ORG_RULESETS_TOKEN, its organization access, and ruleset/bypass visibility."
            raise CheckError(
                f"GitHub GET {endpoint} failed (HTTP {error.code}).{hint}"
            ) from error
        except (URLError, TimeoutError, ValueError, OSError) as error:
            raise CheckError(
                f"GitHub GET {endpoint} failed: network error or invalid JSON response"
            ) from error


def fetch_live(client, organization):
    """Read every organization ruleset, including rules not yet recorded in Git."""
    prefix = f"/orgs/{organization}/rulesets"
    inventory = {}
    page = 1
    while True:
        items = client.get(f"{prefix}?per_page=100&page={page}")
        if not isinstance(items, list):
            raise CheckError(
                "GitHub returned an invalid organization ruleset inventory"
            )
        for item in items:
            if (
                not isinstance(item, dict)
                or type(item.get("id")) is not int
                or item["id"] <= 0
            ):
                raise CheckError("GitHub returned an invalid ruleset inventory entry")
            if item["id"] in inventory:
                raise CheckError(
                    "GitHub returned a duplicate ruleset ID; retry the inventory"
                )
            inventory[item["id"]] = item
        if len(items) < 100:
            break
        page += 1
    result = {}
    for rule_id in sorted(inventory):
        rule = client.get(f"{prefix}/{rule_id}")
        validate_rule(rule, organization, f"Live ruleset {rule_id}")
        if rule["id"] != rule_id:
            raise CheckError(
                f"GitHub returned the wrong definition for ruleset {rule_id}"
            )
        result[rule_id] = rule
    return result


def compare(recorded, live):
    differences = []
    for rule_id in sorted(recorded.keys() | live.keys()):
        before = canonicalize(recorded.get(rule_id))
        after = canonicalize(live.get(rule_id))
        if before == after:
            continue
        if rule_id not in recorded:
            kind = "Untracked live ruleset"
        elif rule_id not in live:
            kind = "Missing live ruleset"
        else:
            kind = "Changed ruleset"
        name = (recorded.get(rule_id) or live[rule_id])["name"]
        difference = "\n".join(
            difflib.unified_diff(
                json.dumps(before, indent=2, ensure_ascii=True).splitlines(),
                json.dumps(after, indent=2, ensure_ascii=True).splitlines(),
                fromfile=f"recorded/{rule_id}",
                tofile=f"live/{rule_id}",
                lineterm="",
            )
        )
        differences.append(f"{kind} {rule_id} ({json.dumps(name)}):\n{difference}")
    return differences


def report(message, summary_path):
    # Indentation prevents data from being interpreted as Actions workflow commands.
    print("\n".join("  " + line for line in message.splitlines()))
    if summary_path:
        # A data value containing backticks must not end the summary's code fence.
        runs = re.findall(r"`+", message)
        fence = "`" * max(3, 1 + max((len(run) for run in runs), default=0))
        with Path(summary_path).open("a") as output:
            output.write(
                f"## Organization ruleset drift\n\n{fence}text\n{message}\n{fence}\n"
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", default="hegemony-sh")
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "rulesets",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate recorded exports without credentials or network access",
    )
    args = parser.parse_args(argv)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    try:
        if not re.fullmatch(r"[A-Za-z0-9-]+", args.org):
            raise CheckError("Invalid organization name")
        recorded = load_recorded(args.rules_dir, args.org)
        if args.validate_only:
            message = f"Validated {len(recorded)} recorded organization rulesets (offline; live drift was not checked)."
            status = 0
        else:
            token = os.environ.get("ORG_RULESETS_TOKEN", "")
            if not token:
                raise CheckError(
                    "ORG_RULESETS_TOKEN is missing. Configure the Actions secret with access to list and read full organization rulesets, including bypass actors."
                )
            live = fetch_live(GitHub(token), args.org)
            differences = compare(recorded, live)
            if differences:
                message = (
                    f"DRIFT: {len(differences)} organization ruleset(s) differ.\n\n"
                    + "\n\n".join(differences)
                )
                status = 1
            else:
                message = f"OK: all {len(recorded)} organization rulesets match the recorded configuration."
                status = 0
    except CheckError as error:
        message = f"ERROR: drift could not be checked. {error}"
        status = 2
    report(message, summary_path)
    return status


if __name__ == "__main__":
    sys.exit(main())
