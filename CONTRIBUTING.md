<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing to Hegemony

GitHub shows this file for every repository in the hegemony-sh organization
that has no `CONTRIBUTING.md` of its own. Where a repository has one, that file
applies and adds the repository's own workflow.

## Licence

Hegemony is licensed under the GNU Affero General Public License, version 3 or
any later version (`AGPL-3.0-or-later`). Your contribution is licensed under the
same terms, and you keep the copyright in it. There is no Contributor License
Agreement.

## Sign off every commit (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO),
version 1.1. A `Signed-off-by:` line certifies that you wrote the change, or
otherwise have the right to submit it under the project licence. Sign off with
`git commit -s` (`--signoff`), which adds a trailer like this:

```text
Signed-off-by: Your Name <your.email@example.com>
```

The DCO GitHub App checks every commit in a pull request: the sign-off's name
and email must match the commit's author or committer. Merge commits and commits
by GitHub bot accounts are skipped.

To add a missing sign-off to every commit on your branch, then update the pull
request:

```bash
git rebase --signoff origin/main
git push --force-with-lease
```

Use the name of the branch your pull request targets in place of `main`.

## AI-assisted commits

A commit written by an AI coding agent is signed off by the person who directs
the agent and submits the work; the agent cannot make the DCO's promise itself.
That person is the commit's committer and adds their own `Signed-off-by:`, while
the agent stays visible as the commit's author or in a `Co-authored-by:`
trailer. An agent must never sign off in its own name. Setting
`GIT_COMMITTER_NAME` and `GIT_COMMITTER_EMAIL` in the agent's environment and
having it commit with `git commit -s` produces exactly that.

## Questions

Licensing questions: [contact@hegemony.sh](mailto:contact@hegemony.sh).
