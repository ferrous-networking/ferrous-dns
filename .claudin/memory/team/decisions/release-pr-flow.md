---
name: release-pr-flow
description: Why releases go through a regenerated chore(release) PR, why the docs deploy rides the release-created dispatch, and the GitHub event rules that shaped both
type: project
scope: ci/release
impact: structural
---

**Decision:** a release is a pull request. `release-pr.yml` (manual dispatch, `patch|minor|major`)
bumps `Cargo.toml` + the docs banners, prepends the section to `CHANGELOG.md` with git-cliff and
opens `chore(release): vX.Y.Z` from `release/vX.Y.Z`. Every push to `main` regenerates an open
release PR for the same version. Merging it makes `release-tag.yml` tag the merge commit, which
starts `release.yml`; that publishes the `CHANGELOG.md` section verbatim
(`scripts/changelog-section.sh`) and sends `repository_dispatch: release-created`, which both
`docker.yml` and `docs.yml` listen to. `site/` is untracked; the docs deploy only on a release.
Chosen with Viudes on 2026-10-23 (branch `ci/release-and-docs-flow`).

**Why:** the old `release-trigger.yml` pushed the bump and tag straight to main with the
`RELEASE_TOKEN` PAT (only possible through the ruleset's admin bypass), and `docs.yml` committed
a regenerated `site/` after every merge, because the sitemap and revision dates change on each
build. That bot commit landed after every merge and filled the release notes.

**What changes for a teammate:**
- Anything that must start another workflow uses `RELEASE_TOKEN`: the release PR (or CI won't
  run on it), the tag push (or `release.yml` won't fire), the dispatch. Events raised with
  `GITHUB_TOKEN` start no workflow, and that includes a release created with it.
- The `github-pages` environment deploys only from branch `main`. That is why docs ride the
  dispatch (`ref` = main) and check out the tag, instead of running on the tag or `on: release`.
- The release PR is regenerated after every merge to main because squash-merging a stale one
  tags changes its notes never list. The next `--unreleased` would then skip them for good.
  `release-tag.yml` refuses a release PR whose branch does not contain main's tip.
  Rewording on the branch is lost on the next regeneration.
- Don't add a git-cliff `footer`, and don't end the body with a blank line: `--prepend` would
  duplicate the first and double the second.

**Rejected:** release-plz / release-please (the maintainer wants to pick when and which bump);
size labels (replaced by type-from-title + subject-from-paths in `pr-triage.yml`).

**Evidence:** plan `composed-gathering-salamander.md`; dry runs of two consecutive prepends; the
stale-merge guard checked in a toy repo.
