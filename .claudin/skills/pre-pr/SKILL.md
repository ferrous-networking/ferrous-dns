---
name: pre-pr
description: Runs the same checks the ferrous-dns PR CI runs (fmt, clippy, tests, doc tests, audit, docs version, optional 60s fuzz) before opening a pull request. Use when the user says "pre-pr", before `gh pr create`, or asks to make sure CI will pass.
---

Mirror of `.github/workflows/ci.yml` for local runs. Run the checks in the order below; on the first failure, fix the root cause and re-run from that step. Report a final checklist of all steps.

## Core gate (always run — CI fails the PR on these)

1. **Formatting**: `cargo fmt --all -- --check`
2. **Clippy**: `cargo clippy --all-targets --all-features --workspace -- -D warnings` (CI passes `--workspace`; `make clippy` is equivalent because the root manifest is virtual)
3. **Tests**: `cargo test --all-features --workspace`
4. **Doc tests**: `cargo test --doc --all-features --workspace`
5. **Security audit**: `cargo audit` (skip with a note if `cargo-audit` is not installed — do not install it silently)
6. **Docs version consistency**: `bash scripts/check-docs-version.sh --fix` — version banners in `docs/` must match the workspace version in the root `Cargo.toml`. If `--fix` changed files, stage/commit them with the PR.

## Optional heavy checks (ask the user before running)

- **Short fuzz** (needs nightly + cargo-fuzz 0.13.2, ~5 min total). Only relevant when the change touches `crates/infrastructure/src/dns/` (parsers/serializers) or `fuzz/`. For each target — `query_fast_path`, `response_lowercase_0x20`, `dnssec_records`, `proxy_protocol_v2`, `blocklist_text`:
  `cd fuzz && cargo +nightly fuzz run <target> -- -dict=fuzz/dict/dns.dict -max_total_time=60 -timeout=25 -rss_limit_mb=4096`
  On a crash: follow the repo policy — minimize (`tmin`), add a regression test in `crates/infrastructure/tests/fuzz_regressions.rs`, then fix.
- **Coverage** (`cargo tarpaulin`) and the **ARM64 cross-build** run in CI but are not merge gates; skip locally.

## Skipped on purpose

- `benchmark` job — disabled in CI (`if: false`).
- `dependency-review` — GitHub-only action, nothing to run locally.

## Last: PR title

Remind the user the PR title must follow Conventional Commits (`feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `chore`, ...) — CI validates it on the PR itself, not on local commits.
