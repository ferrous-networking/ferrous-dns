# 📜 Ferrous DNS - Scripts

Helper scripts used by the release workflow and CI.

## 📋 Available Scripts

### `bump-version.sh`

Sets the workspace version in the root `Cargo.toml` (every crate inherits it
through `version.workspace = true`) and rewrites the "Current release" banners
under `docs/` to match.

```bash
./scripts/bump-version.sh [major|minor|patch|VERSION]

./scripts/bump-version.sh patch   # 0.9.24 -> 0.9.25
./scripts/bump-version.sh 1.2.3   # set a specific version
```

You don't normally run it by hand: the **Release PR** workflow
(`.github/workflows/release-pr.yml`) runs it when it opens a release pull
request.

### `check-docs-version.sh`

Fails when the docs drift from the workspace: a "Current release" banner that
names another version, or no mention of the current minor series in
`docs/changelog.md`. CI runs it on every pull request.

```bash
./scripts/check-docs-version.sh
```

### `changelog-section.sh`

Prints one release's section of `CHANGELOG.md`, and fails when it is missing or
lists no changes. The Release PR workflow shows it in the release pull request
and the Release workflow publishes it as the GitHub release notes, so the two
always match.

```bash
./scripts/changelog-section.sh v0.9.24
```

### `release-milestone.sh`

Files a release under its milestone and closes it. Every pull request merged
since the previous tag, and every issue it closes, is set to the milestone
titled `vX.Y.Z` (or `vX.Y.Z — …`), whatever milestone it had. Anything still
open in it moves to the next open milestone by version; with no later
milestone, it stays open and the script warns. A release with no milestone,
such as a patch, gets one. The GitHub release notes gain a link to it. Running
it again changes nothing more.

```bash
./scripts/release-milestone.sh v0.10.0 origin/main --dry-run   # before the tag exists
./scripts/release-milestone.sh v0.10.0                         # what release.yml runs
```

`--dry-run` only reads, and prints what it would change. The **Release**
workflow runs it once the release and its binaries are published.

---

## 🚀 Releasing

A release is a pull request; nothing is pushed to `main` directly.

1. Run the **Release PR** workflow from the Actions tab and pick
   `patch`, `minor` or `major` (or run `make release-patch` /
   `release-minor` / `release-major`, which call `gh workflow run`).
2. It opens `chore(release): vX.Y.Z` with the version bump, the docs banners and
   the new `CHANGELOG.md` section, and regenerates it after every merge to
   `main` until it is merged. Review it like any other PR; reword the notes on
   that branch right before merging. `make changelog` previews them locally.
3. Merge it. **Release Tag** tags the merge commit, and the tag starts
   **Release**: binaries, GitHub release (notes taken from `CHANGELOG.md`),
   Docker image, and the docs site. It also closes the release's milestone,
   with every pull request and issue the release shipped filed under it.

Versions follow [Semantic Versioning](https://semver.org/); while on 0.x, a
release with new features is still a patch bump unless something breaks.

---

## 📄 License

MIT OR Apache-2.0
