---
name: pre-pr
description: Runs the same checks the ferrous-dns PR CI runs (fmt, clippy, tests, doc tests, audit, docs version) before opening a pull request. Use when the user says "pre-pr", before `gh pr create`, or asks to make sure CI will pass.
---

Mirror of `.github/workflows/ci.yml` for local runs. Run the checks in the order below; on the first failure, fix the root cause and re-run from that step. Report a final checklist of all steps.

## Core gate (always run — CI fails the PR on these)

1. **Formatting**: `cargo fmt --all -- --check`
2. **Clippy**: `cargo clippy --all-targets --all-features --workspace -- -D warnings` (CI passes `--workspace`; `make clippy` is equivalent because the root manifest is virtual)
3. **Tests**: `cargo test --all-features --workspace`
4. **Doc tests**: `cargo test --doc --all-features --workspace`
5. **Security audit**: `cargo audit` (skip with a note if `cargo-audit` is not installed — do not install it silently)
6. **Docs version consistency**: `bash scripts/check-docs-version.sh` — version banners in `docs/` must match the workspace version in the root `Cargo.toml`. Only the release PR moves the version (`scripts/bump-version.sh` rewrites the banners with it), so drift anywhere else means a version was edited by hand.
7. **Docs build** (only when `docs/`, `mkdocs.yml`, `requirements.txt`, `ROADMAP.md` or `CHANGELOG.md` changed): `mkdocs build --strict` with the pinned toolchain (`pip install -r requirements.txt` in a venv). `docs.yml` runs the same build on those pull requests.

## Skipped on purpose

- **Fuzz** and **coverage** (`cargo tarpaulin`) — left to CI; not run locally.
- **ARM64 cross-build** — runs in CI but is not a merge gate.
- `benchmark` job — disabled in CI (`if: false`).
- `dependency-review` — GitHub-only action, nothing to run locally.

## Last: PR title

Remind the user the PR title must follow the conventions in `.claudin/rules/pr-titles.md` — CI validates it on the PR itself, not on local commits.
