#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Compare recorded GitHub rulesets with the live ones, using GET requests only.

One checker for two scopes, kept byte-identical in the organisation's
``.github`` repository and in the platform repository:

* ``--org hegemony-sh`` compares the organisation rulesets recorded under
  ``rulesets/`` with the organisation's live ones.
* ``--repo hegemony-sh/hegemony`` compares the repository rulesets recorded
  under ``.github/rulesets/`` with the repository's own live ones (the ones
  it inherits from the organisation are the organisation check's business).

Modes:

* ``--validate-only`` checks the recorded files offline, without a token.
* Without it, the live rulesets are read through the API and compared, by
  id. A recorded file that has no ``id`` yet (one written for an import,
  before GitHub assigned the id) is matched by name once, and the check then
  reports the id to record as a difference, so a file never stays matched by
  name for good.
* ``--export`` writes the live definitions into the recorded files: the first
  recording after an import, or a refresh after a reviewed settings change.
  The diff is then reviewed in a pull request. It still only reads from
  GitHub.

Exit codes: 0 for a match (or a completed offline validation or export), 1
for drift, 2 when the check could not be completed. An access failure is
never reported as a match.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, OpenerDirector, Request, build_opener

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
PAGE_SIZE = 100
#: Response-only fields: not policy, not recorded, not compared.
RESPONSE_METADATA = {"_links", "node_id", "created_at", "updated_at", "current_user_can_bypass"}
#: The order the recorded files keep their top-level keys in.
EXPORT_ORDER = (
    "id",
    "name",
    "target",
    "source_type",
    "source",
    "enforcement",
    "conditions",
    "rules",
    "bypass_actors",
)
REPOSITORY_SELECTORS = {"repository_name", "repository_id", "repository_property"}
UNORDERED_PARAMETERS = {
    "allowed_merge_methods",
    "required_status_checks",
    "required_reviewers",
    "required_deployment_environments",
    "workflows",
}
TARGETS = {"branch", "tag", "push", "repository"}
ENFORCEMENTS = {"active", "disabled", "evaluate"}
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

Json = Any


class CheckError(Exception):
    """The check could not establish whether the live policy matches."""


@dataclass(frozen=True)
class Scope:
    """Whose rulesets are checked: an organisation's, or one repository's own."""

    owner: str
    repository: str = ""

    @classmethod
    def parse(cls, org: str | None, repo: str | None) -> Scope:
        """Build the scope from the ``--org`` or ``--repo`` argument."""
        if (org is None) == (repo is None):
            raise CheckError("Give exactly one of --org ORGANIZATION or --repo OWNER/NAME")
        if org is not None:
            if not NAME_PATTERN.fullmatch(org):
                raise CheckError("Invalid organization name")
            return cls(org)
        owner, separator, name = (repo or "").partition("/")
        if not separator or not NAME_PATTERN.fullmatch(owner) or not NAME_PATTERN.fullmatch(name):
            raise CheckError("Invalid repository name; expected OWNER/NAME")
        return cls(owner, name)

    @property
    def is_repository(self) -> bool:
        """True for one repository's own rulesets."""
        return bool(self.repository)

    @property
    def label(self) -> str:
        """The word the messages use for the scope."""
        return "repository" if self.is_repository else "organization"

    @property
    def source_type(self) -> str:
        """The ``source_type`` the API reports for rulesets of this scope."""
        return "Repository" if self.is_repository else "Organization"

    @property
    def source(self) -> str:
        """The ``source`` the API reports for rulesets of this scope."""
        return f"{self.owner}/{self.repository}" if self.is_repository else self.owner

    @property
    def endpoint(self) -> str:
        """The rulesets collection of this scope, without a query string."""
        if self.is_repository:
            return f"/repos/{self.owner}/{self.repository}/rulesets"
        return f"/orgs/{self.owner}/rulesets"

    def inventory_endpoint(self, page: int) -> str:
        """One page of the scope's own rulesets (a repository's inherited ones excluded)."""
        query = f"per_page={PAGE_SIZE}&page={page}"
        if self.is_repository:
            query = "includes_parents=false&" + query
        return f"{self.endpoint}?{query}"

    @property
    def token_variable(self) -> str:
        """The environment variable the live check reads its token from."""
        return "REPO_RULESETS_TOKEN" if self.is_repository else "ORG_RULESETS_TOKEN"

    def default_rules_dir(self, root: Path) -> Path:
        """Where the scope's rulesets are recorded in a checkout."""
        return root / ".github" / "rulesets" if self.is_repository else root / "rulesets"


def unique_keys(pairs: list[tuple[str, Json]]) -> dict[str, Json]:
    """Object hook that refuses a JSON object with a repeated key."""
    result: dict[str, Json] = {}
    for key, value in pairs:
        if key in result:
            raise CheckError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_rule(rule: Json, scope: Scope, label: str) -> None:
    """Refuse a ruleset that is not a complete, well-formed export of this scope."""
    if not isinstance(rule, dict):
        raise CheckError(f"{label}: expected a ruleset object")
    required = {
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
            f"{label}: missing fields {', '.join(sorted(missing))}; a full "
            f"{scope.label} export with bypass visibility is required"
        )
    if "id" in rule and (type(rule["id"]) is not int or rule["id"] <= 0):
        raise CheckError(f"{label}: id must be a positive integer")
    if (
        rule["source_type"] != scope.source_type
        or not isinstance(rule["source"], str)
        or rule["source"].lower() != scope.source.lower()
    ):
        raise CheckError(f"{label}: expected a {scope.label} ruleset belonging to {scope.source}")
    if not isinstance(rule["name"], str) or not rule["name"]:
        raise CheckError(f"{label}: name must be a nonempty string")
    if not isinstance(rule["target"], str) or rule["target"] not in TARGETS:
        raise CheckError(f"{label}: unsupported ruleset target")
    if not isinstance(rule["enforcement"], str) or rule["enforcement"] not in ENFORCEMENTS:
        raise CheckError(f"{label}: unsupported enforcement value")
    conditions = rule["conditions"]
    if not isinstance(conditions, dict):
        raise CheckError(f"{label}: conditions must be an object")
    selectors = REPOSITORY_SELECTORS & conditions.keys()
    if scope.is_repository:
        if selectors:
            raise CheckError(f"{label}: a repository ruleset carries no repository selector")
    elif len(selectors) != 1:
        raise CheckError(f"{label}: exactly one organization repository selector is required")
    for selector in selectors:
        if not isinstance(conditions[selector], dict) or not conditions[selector]:
            raise CheckError(f"{label}: repository selector must be a nonempty object")
    if rule["target"] in {"branch", "tag"} and not isinstance(conditions.get("ref_name"), dict):
        raise CheckError(f"{label}: branch/tag rulesets need ref_name conditions")
    if not isinstance(rule["rules"], list) or not isinstance(rule["bypass_actors"], list):
        raise CheckError(f"{label}: rules and bypass_actors must be arrays")


def load_recorded(directory: Path, scope: Scope) -> dict[Path, Json]:
    """Read every recorded ruleset file, in path order; refuse duplicates."""
    result: dict[Path, Json] = {}
    ids: dict[int, Path] = {}
    names: dict[str, Path] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            rule = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
        except (OSError, ValueError) as error:
            raise CheckError(f"Cannot read {path}: {error}") from error
        validate_rule(rule, scope, str(path))
        if "id" in rule:
            if rule["id"] in ids:
                raise CheckError(f"Duplicate recorded ruleset ID: {rule['id']}")
            ids[rule["id"]] = path
        elif rule["name"] in names:
            raise CheckError(f"Duplicate recorded ruleset name without an id: {rule['name']}")
        else:
            names[rule["name"]] = path
        result[path] = rule
    if not result:
        raise CheckError(f"No ruleset JSON files found in {directory}")
    return result


def canonicalize(value: Json, path: tuple[str, ...] = ()) -> Json:
    """Drop response metadata and order only the arrays GitHub treats as sets."""
    if isinstance(value, dict):
        values = dict(value)
        if not path:
            values = {key: item for key, item in values.items() if key not in RESPONSE_METADATA}
        if path == ("conditions", "repository_name"):
            # The UI export may omit this optional false-valued API setting.
            values.setdefault("protected", False)
        return {key: canonicalize(item, (*path, key)) for key, item in sorted(values.items())}
    if isinstance(value, list):
        values = [canonicalize(item, (*path, "*")) for item in value]
        unordered = (
            path in {("rules",), ("bypass_actors",)}
            or (
                path[:1] == ("conditions",) and path[-1] in {"include", "exclude", "repository_ids"}
            )
            or (path[:3] == ("rules", "*", "parameters") and path[-1] in UNORDERED_PARAMETERS)
        )
        if unordered:
            values.sort(key=lambda item: json.dumps(item, sort_keys=True))
        return values
    return value


def policy(rule: Json | None) -> Json | None:
    """The part of a ruleset that is compared: everything but its id."""
    if rule is None:
        return None
    return canonicalize({key: value for key, value in rule.items() if key != "id"})


class NoRedirect(HTTPRedirectHandler):
    """Never follow a redirect: the token must not reach another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class GitHub:
    """A minimal GET-only client for the rulesets API."""

    def __init__(self, token: str, opener: OpenerDirector | None = None) -> None:
        self.token = token
        self.opener = opener or build_opener(NoRedirect())

    def get(self, endpoint: str, token_variable: str) -> Json:
        """GET one endpoint; an error names the token variable, never the response."""
        request = Request(
            API_ROOT + endpoint,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "hegemony-ruleset-drift",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response, object_pairs_hook=unique_keys)
        except HTTPError as error:
            # Neither the response body nor the request headers are printed.
            hint = ""
            if error.code in {401, 403, 404}:
                hint = f" Verify {token_variable}, its access, and ruleset/bypass visibility."
            raise CheckError(f"GitHub GET {endpoint} failed (HTTP {error.code}).{hint}") from error
        except (URLError, TimeoutError, ValueError, OSError) as error:
            raise CheckError(
                f"GitHub GET {endpoint} failed: network error or invalid JSON response"
            ) from error


def fetch_live(client: GitHub, scope: Scope) -> dict[int, Json]:
    """Read every live ruleset of the scope, the ones not recorded included."""
    inventory: dict[int, Json] = {}
    page = 1
    while True:
        items = client.get(scope.inventory_endpoint(page), scope.token_variable)
        if not isinstance(items, list):
            raise CheckError(f"GitHub returned an invalid {scope.label} ruleset inventory")
        for item in items:
            if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] <= 0:
                raise CheckError("GitHub returned an invalid ruleset inventory entry")
            if item["id"] in inventory:
                raise CheckError("GitHub returned a duplicate ruleset ID; retry the inventory")
            if item.get("source_type", scope.source_type) != scope.source_type:
                continue  # an inherited ruleset the other scope's check owns
            inventory[item["id"]] = item
        if len(items) < PAGE_SIZE:
            break
        page += 1
    result: dict[int, Json] = {}
    for rule_id in sorted(inventory):
        rule = client.get(f"{scope.endpoint}/{rule_id}", scope.token_variable)
        validate_rule(rule, scope, f"Live ruleset {rule_id}")
        if rule.get("id") != rule_id:
            raise CheckError(f"GitHub returned the wrong definition for ruleset {rule_id}")
        result[rule_id] = rule
    return result


def _difference(kind: str, rule_id: int | str, name: str, before: Json, after: Json) -> str:
    diff = "\n".join(
        difflib.unified_diff(
            json.dumps(before, indent=2, ensure_ascii=True).splitlines(),
            json.dumps(after, indent=2, ensure_ascii=True).splitlines(),
            fromfile=f"recorded/{rule_id}",
            tofile=f"live/{rule_id}",
            lineterm="",
        )
    )
    return f"{kind} {rule_id} ({json.dumps(name)}):\n{diff}"


def compare(recorded: dict[Path, Json], live: dict[int, Json]) -> list[str]:
    """Match recorded files with live rulesets (by id, else once by name) and diff them."""
    differences: list[str] = []
    claimed: set[int] = set()
    by_name: list[tuple[Path, Json]] = []
    for path, rule in recorded.items():
        if "id" not in rule:
            by_name.append((path, rule))
            continue
        rule_id = rule["id"]
        claimed.add(rule_id)
        before, after = policy(rule), policy(live.get(rule_id))
        if rule_id not in live:
            differences.append(
                _difference("Missing live ruleset", rule_id, rule["name"], before, after)
            )
        elif before != after:
            differences.append(_difference("Changed ruleset", rule_id, rule["name"], before, after))
    for path, rule in by_name:
        candidates = [
            rule_id
            for rule_id, item in sorted(live.items())
            if item["name"] == rule["name"] and rule_id not in claimed
        ]
        if len(candidates) > 1:
            raise CheckError(
                f"{path.name}: several live rulesets are named {rule['name']!r}; record the id"
            )
        if not candidates:
            differences.append(
                _difference("Missing live ruleset", path.name, rule["name"], policy(rule), None)
            )
            continue
        rule_id = candidates[0]
        claimed.add(rule_id)
        before, after = policy(rule), policy(live[rule_id])
        if before != after:
            differences.append(_difference("Changed ruleset", rule_id, rule["name"], before, after))
        differences.append(
            f"Unrecorded ruleset id {rule_id} ({json.dumps(rule['name'])}): {path.name} was "
            f'matched by name; add "id": {rule_id} to the file (or run --export).'
        )
    for rule_id in sorted(set(live) - claimed):
        rule = live[rule_id]
        differences.append(
            _difference("Untracked live ruleset", rule_id, rule["name"], None, policy(rule))
        )
    return differences


def export_live(live: dict[int, Json], recorded: dict[Path, Json], directory: Path) -> list[Path]:
    """Write every live ruleset into the recorded files; return the paths written."""
    by_id = {rule["id"]: path for path, rule in recorded.items() if "id" in rule}
    by_name = {rule["name"]: path for path, rule in recorded.items() if "id" not in rule}
    for name, path in by_name.items():
        matches = [i for i, rule in live.items() if rule["name"] == name and i not in by_id]
        if len(matches) > 1:
            raise CheckError(f"{path.name}: several live rulesets are named {name!r}; record the id")
    reserved = set(recorded)
    written: list[Path] = []
    for rule_id, rule in sorted(live.items()):
        path = by_id.get(rule_id) or by_name.pop(rule["name"], None)
        if path is None:
            stem = re.sub(r"[^A-Za-z0-9._-]+", "-", rule["name"]).strip("-") or str(rule_id)
            path = directory / f"{stem}.json"
            if path in reserved:
                path = directory / f"{stem}-{rule_id}.json"
                suffix = 2
                while path in reserved:
                    path = directory / f"{stem}-{rule_id}-{suffix}.json"
                    suffix += 1
        reserved.add(path)
        document = {key: rule[key] for key in EXPORT_ORDER if key in rule}
        document.update(
            {
                key: value
                for key, value in sorted(rule.items())
                if key not in document and key not in RESPONSE_METADATA
            }
        )
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    return written


def report(message: str, summary_path: str | None) -> None:
    """Print the outcome, and append it to the job summary when there is one."""
    # Indentation prevents data from being interpreted as Actions workflow commands.
    print("\n".join("  " + line for line in message.splitlines()))
    if summary_path:
        # A data value containing backticks must not end the summary's code fence.
        runs = re.findall(r"`+", message)
        fence = "`" * max(3, 1 + max((len(run) for run in runs), default=0))
        with Path(summary_path).open("a", encoding="utf-8") as output:
            output.write(f"## Ruleset drift\n\n{fence}text\n{message}\n{fence}\n")


def main(argv: list[str] | None = None) -> int:
    """Run the check; the exit code says match, drift, or could not check."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--org", help="check this organization's rulesets (rulesets/)")
    parser.add_argument("--repo", help="check this repository's own rulesets (.github/rulesets/)")
    parser.add_argument("--rules-dir", type=Path, help="where the rulesets are recorded")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the recorded files without credentials or network access",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="write the live rulesets into the recorded files instead of comparing",
    )
    args = parser.parse_args(argv)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    try:
        scope = Scope.parse(args.org, args.repo)
        rules_dir = args.rules_dir or scope.default_rules_dir(Path(__file__).resolve().parents[1])
        if args.export and args.validate_only:
            raise CheckError("--export and --validate-only exclude each other")
        if args.export and not rules_dir.is_dir():
            raise CheckError(f"{rules_dir} is not a directory")
        recorded = (
            {}
            if args.export and not any(rules_dir.glob("*.json"))
            else load_recorded(rules_dir, scope)
        )
        unrecorded = sorted(rule["name"] for rule in recorded.values() if "id" not in rule)
        if args.validate_only:
            message = (
                f"Validated {len(recorded)} recorded {scope.label} rulesets "
                "(offline; live drift was not checked)."
            )
            if unrecorded:
                message += (
                    f" {len(unrecorded)} file(s) carry no id yet and are matched by name "
                    f"until it is recorded: {', '.join(unrecorded)}."
                )
            status = 0
        else:
            token = os.environ.get(scope.token_variable, "")
            if not token:
                raise CheckError(
                    f"{scope.token_variable} is missing. Configure a token that can list "
                    f"and read the {scope.label} rulesets of {scope.source}, bypass actors "
                    "included."
                )
            live = fetch_live(GitHub(token), scope)
            if args.export:
                written = export_live(live, recorded, rules_dir)
                stale = sorted(
                    path.name
                    for path in recorded
                    if path not in written
                )
                message = (
                    f"Exported {len(written)} live {scope.label} ruleset(s) of {scope.source} to "
                    f"{rules_dir}: {', '.join(path.name for path in written)}. Review the diff "
                    "and commit it."
                )
                if stale:
                    message += (
                        f" Recorded but no longer live (left as they are): {', '.join(stale)}."
                    )
                status = 0
            else:
                differences = compare(recorded, live)
                if differences:
                    message = (
                        f"DRIFT: {len(differences)} {scope.label} ruleset difference(s) for "
                        f"{scope.source}.\n\n" + "\n\n".join(differences)
                    )
                    status = 1
                else:
                    message = (
                        f"OK: all {len(recorded)} {scope.label} rulesets of {scope.source} "
                        "match the recorded configuration."
                    )
                    status = 0
    except CheckError as error:
        message = f"ERROR: drift could not be checked. {error}"
        status = 2
    report(message, summary_path)
    return status


if __name__ == "__main__":
    sys.exit(main())
