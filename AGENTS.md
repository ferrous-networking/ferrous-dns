# ferrous-dns — agent guide

ferrous-dns is a security-focused, DNSSEC-validating DNS resolver and content filter written in Rust. This file is the entry point for AI coding agents; detailed standards live in `.claudin/rules/`.

## Build and test

- `make ci` — formatting check, clippy with `-D warnings`, and the full test suite; run before every commit
- `make pre-commit` — formatting, clippy, tests
- `make test` / `make bench` / `make coverage` — tests, criterion benchmarks, tarpaulin coverage
- `cargo run --release --bin ferrous-dns -- --config config/config.toml` — run the server; on failure check the port, config path, and file permissions first
- The `/verify` and `/pre-pr` skills in `.claudin/skills/` mirror the CI checks (`/pre-pr` adds `cargo audit` and docs version checks) — run them before pushing or opening a PR

## Workspace map (Clean Architecture)

`domain` (entities, pure business rules) → `application` (use cases, ports) → `infrastructure` (adapters) → `api` (HTTP) → `cli` (binary, DI in `cli/src/wiring/`). See `.claudin/rules/architecture.md` for the dependency rules and the port/use-case pattern.

## Contribution rules

- Conventional Commits; branches `feat/`, `fix/`, `docs/`; PR title rules in `.claudin/rules/pr-titles.md` (CI validates the title)
- Direct commits to `main`/`master` are blocked by a PreToolUse hook in `.claudin/settings.json` (user-local; opt-in per machine) — create a branch and open a PR instead
- Architecture, code, and web UI standards: `.claudin/rules/architecture.md`, `code-standards.md`, `web.md`, `web-architecture.md`
- Fuzz crash policy: minimize, regression test, then fix (`fuzz/AGENTS.md`); `./scripts/check-fuzz-regressions.sh` runs the harnesses — must stay green
- Keep `site/` and `.vitepress/` as generated artifacts only; never edit them by hand
- Verify license/AGPL compatibility before adding a dependency; run `cargo audit` before committing
- Remove dead code immediately; update `docs/` and `config/` when adding a feature
- `CONTRIBUTING.md` and `SECURITY.md` cover the human-facing workflow and vulnerability reporting
