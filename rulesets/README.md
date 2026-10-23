<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Organization rulesets

These files record the shared branch and tag policies for `hegemony-sh` in
GitHub's organization ruleset export format. They were supplied from the live
organization settings on 2026-10-21. Their rules, ref patterns and bypass actors
were also checked against the inherited rules visible on
`hegemony-sh/hegemony`.

All three rulesets are active and target **every repository** through
`conditions.repository_name.include: ["~ALL"]`, with no repository exclusions.
The ref patterns below select the branches or tags within those repositories.
The exports preserve the existing policy, including its bypasses. Merging these
files does not update GitHub settings; there is no automatic deployment.
The [drift check](#automated-drift-check) compares these files with live settings.

## Policies

| File | Live organization ruleset | Ref pattern |
| --- | --- | --- |
| [protect-main.json](protect-main.json) | [21484617](https://github.com/organizations/hegemony-sh/settings/rules/21484617) | `refs/heads/main` |
| [protect-develop.json](protect-develop.json) | [21484992](https://github.com/organizations/hegemony-sh/settings/rules/21484992) | `refs/heads/develop` |
| [protect-release-tags.json](protect-release-tags.json) | [21485846](https://github.com/organizations/hegemony-sh/settings/rules/21485846) | `refs/tags/v*` |

Both branch policies require a pull request, code-owner review and resolution
of review discussions, and block deletion and force pushes. Their general
approval count is zero. `main` dismisses stale approvals and allows only merge
commits; `develop` keeps approvals and allows merge commits or squash merges.
Both enable Copilot code review, with review-on-push and draft review disabled.
The JSON also preserves GitHub's extra-approval setting for unattributed changes.

The tag policy blocks updates, deletion and force pushes. It does not restrict
creation of new matching tags or require signatures. None of these three
policies requires CI status checks or targets LTS branches such as `3.x`.

All three allow `OrganizationAdmin` to bypass with mode `always`. The files
retain that existing access policy. A narrower release identity or a different
bypass policy would be a separate policy change.

## Relationship to repository rules

GitHub aggregates all applicable organization and repository rulesets. When
requirements overlap, the strictest applies. A repository ruleset with
`require_code_owner_review: false` does not disable an inherited requirement.
See [GitHub's rule layering documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#about-rule-layering).

Keep shared protections here. Repository-specific requirements, such as the
names of required CI checks, belong in the affected repository. Give those
supplemental rulesets distinct names so operators can identify each layer.
For example, Hegemony can require `CI` and `DCO` locally without copying the
organization policies. Its LTS ruleset remains necessary while these
organization rules do not cover those branches.

Bypass permission is scoped to each ruleset. For a direct release push to
`main`, the release identity must bypass every applicable rule that would block
that push. A GitHub App or a PAT belonging to someone outside the organization
administrator role does not gain organization bypass by being added to a
repository ruleset. Conversely, an organization administrator's existing bypass
does not bypass a new repository ruleset with an empty bypass list. Check the
authenticated release identity at both levels when changing release automation.

## Automated drift check

[Organization ruleset drift](../.github/workflows/ruleset-drift.yml) runs daily
at 06:17 UTC (07:17 in winter and 08:17 in summer in Prague), when changes to the
rulesets or monitor merge into `main`, and on manual dispatch. Pull requests
run only the offline tests and export validation. The live comparison and its
organization credential are restricted to `hegemony-sh/.github` on `main`.
That job selects the organization's self-hosted runner through the
`CI_RUNNER` variable, as the platform repository's workflows do, and falls
back to `ubuntu-latest` when the variable is unset. The offline job stays on
GitHub-hosted `ubuntu-latest` on purpose: this repository is public and the
job runs on pull requests from forks, whose code must not reach a shared
self-hosted runner.

The checker, [`scripts/check_ruleset_drift.py`](../scripts/check_ruleset_drift.py),
and its tests are shared with the platform repository, `hegemony-sh/hegemony`,
which runs the same two files against its own repository rulesets
(`--repo hegemony-sh/hegemony`, recorded under `.github/rulesets/` there);
this repository runs them with `--org hegemony-sh`. The two copies are kept
byte-identical, so a change made in one repository is copied to the other.

The checker reads the full organization inventory, follows pagination, and
compares rulesets by ID. It detects changed definitions, missing live rulesets,
and live rulesets missing from this repository. The comparison includes
repository targeting, exclusions, ref patterns, rules, enforcement and bypass
actors. It ignores response-only metadata, the ordering of known unordered
lists, and an omitted `repository_name.protected` value when it means `false`.
Unknown policy fields remain part of the comparison.

The checker makes GET requests only and never updates a ruleset. The
comparison does not touch the recorded files either; only `--export` (below)
rewrites them, from the live definitions, for a reviewed refresh. A
discrepancy needs a reviewed policy change or a correction of the live
settings through the maintenance process below.

### Configure the credential

Add a repository Actions secret named **`ORG_RULESETS_TOKEN`** in
[Settings → Secrets and variables → Actions](https://github.com/hegemony-sh/.github/settings/secrets/actions).
Use a token authorized to list and read the organization's complete rulesets,
including bypass actors. The workflow's built-in `GITHUB_TOKEN` is insufficient
for this organization-wide API access.

- A classic PAT needs `admin:org`, and its owner needs access to manage the
  organization's rulesets.
- For a fine-grained PAT, select `hegemony-sh` as resource owner and grant
  organization **Administration: read and write**. GitHub currently requires
  this permission even for these GET endpoints and bypass visibility; the
  checker itself performs only reads.

See the permissions for [listing organization rulesets](https://docs.github.com/en/rest/orgs/rules#get-all-organization-repository-rulesets)
and [reading a ruleset](https://docs.github.com/en/rest/orgs/rules#get-an-organization-repository-ruleset).
Store the token in the Actions secret, and replace it there when it expires or
is rotated. No organization credential is exposed to pull-request jobs.

After merging the workflow and configuring the secret, open
[Actions → Organization ruleset drift](https://github.com/hegemony-sh/.github/actions/workflows/ruleset-drift.yml),
choose **Run workflow**, and select `main`. A successful comparison establishes
that the secret can read the full inventory and that the committed rules match.
A manual run on another branch performs offline validation only.

### Results and notifications

A successful live check reports the number of matching rulesets. Drift fails
the workflow and puts readable differences in the job summary and logs, with
`recorded` as the old side and `live` as the new side. Missing or expired
credentials, hidden bypass information, invalid exports and API failures also
fail the workflow, with an error explaining that drift could not be checked.
An access failure is never reported as a match.

Use [GitHub Actions notifications](https://docs.github.com/en/subscriptions-and-notifications/how-tos/managing-github-actions-notifications)
and select **Only notify for failed workflows** to receive failures without
successful-run notifications. Scheduled-run notifications go to the user who
last changed the cron schedule, subject to their notification settings.
Unresolved drift continues to fail subsequent checks; the workflow does not
open issues or send separate messages.

GitHub can delay scheduled runs and disables schedules in public repositories
after 60 days without repository activity. If this governance repository is
inactive, re-enable the workflow in Actions; a manual run remains available.
See [GitHub's schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

### Local verification

Python 3.10 or newer is sufficient; the checker and tests use the standard
library only. From the repository root:

```sh
python3 -m unittest tests/test_ruleset_drift.py -v
python3 scripts/check_ruleset_drift.py --org hegemony-sh --validate-only
```

For a live check, set `ORG_RULESETS_TOKEN` in your environment using the same
permissions as the Actions secret, then run:

```sh
python3 scripts/check_ruleset_drift.py --org hegemony-sh
```

To refresh the recorded files from the live definitions, after a reviewed
change in the organization settings or when a new ruleset was created, run
the same command with `--export`, review the diff and commit it:

```sh
python3 scripts/check_ruleset_drift.py --org hegemony-sh --export
```

The export reads from GitHub and writes only to `rulesets/`. A live ruleset
that has no file yet gets one named after it. A file recorded without an
`id` (one written before GitHub assigned it) is matched by name once, and
the check reports the id to record as a difference until it is recorded.

Exit codes are `0` for a match (or a completed offline validation or export),
`1` for drift, and `2` when the check cannot complete. Offline validation is
explicitly marked as such and never claims that the live configuration was
checked.

## Review and apply changes

1. Edit the affected export and its description here in a pull request. Review
   repository selectors and exclusions, ref patterns, rules, enforcement and
   bypass actors together. The current `~ALL` scope means a shared-policy change
   affects matching refs across the organization, including this repository.
2. After the change is reviewed, an organization owner or another authorized
   ruleset manager updates the existing organization ruleset by its ID above.
   In GitHub, use organization **Settings → Repository → Rulesets**. Keep each
   repository's supplemental policies at repository scope.
3. Export the live organization ruleset again and compare it with the reviewed
   file to verify that the settings agree. If an urgent operational change
   happens first, promptly record and review the resulting export here.
4. Manually dispatch any Scorecard workflow used for governance evidence after
   changing the live rules. Its `branch_protection_rule` trigger listens to
   classic branch-protection changes; ruleset changes have a separate webhook
   event and do not trigger that workflow automatically.

Import creates another ruleset; it does not update an existing one with the
same name or turn the stored ID into an update request. Use the existing
ruleset IDs for maintenance. Import these exports at organization scope only
when intentionally creating a new ruleset, then record its assigned ID and
recheck its repository targeting and bypass actors.

See [GitHub's organization ruleset management documentation](https://docs.github.com/en/organizations/managing-organization-settings/managing-rulesets-for-repositories-in-your-organization).

## Export and compare

`python3 scripts/check_ruleset_drift.py --org hegemony-sh --export` records
every live ruleset at once (see [Local verification](#local-verification)).
The manual steps below do the same for one ruleset with GitHub CLI and `jq`.

The organization settings UI can export a ruleset. With suitable API access,
use the **organization** endpoint so the response includes repository targeting.
The repository-scoped inherited-rules view omits those selectors and cannot
supply a complete organization export.

For example, run this from the repository root with Bash, GitHub CLI and `jq`:

```bash
gh api orgs/hegemony-sh/rulesets/21484617 \
  --jq '{id, name, target, source_type, source, enforcement, conditions, rules, bypass_actors}' \
  > /tmp/protect-main.live.json

diff -u \
  <(jq -S . rulesets/protect-main.json) \
  <(jq -S . /tmp/protect-main.live.json)
```

Repeat for the other IDs and filenames. No diff means the recorded settings
match the live export. The projection removes response-only links, timestamps,
node IDs and caller-specific bypass capability while retaining every policy
field present in these exports. Review new API policy fields before discarding
them during a future refresh.

The required token permissions are documented in
[GitHub's organization rules API](https://docs.github.com/en/rest/orgs/rules).
A classic token needs the `admin:org` scope for these endpoints. Keep credentials
out of the repository and use the settings UI if API access is unavailable.
