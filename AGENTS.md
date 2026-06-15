# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working directory

The Cargo workspace lives in `ferrous-dns/` (this directory). Run all `cargo`/`make` commands from here, not from the parent `ferrous-networking/` wrapper directory.

## Build, test, lint, format

- Build: `cargo build` (debug) / `cargo build --release`
- Test (all): `cargo test --all-features --workspace`
  - Unit only: `cargo test --lib --all-features --workspace`
  - Integration only: `cargo test --test '*' --all-features --workspace`
  - Doc tests: `cargo test --doc --all-features --workspace`
- Format: `cargo fmt --all` (check: `cargo fmt --all -- --check`)
- Lint: `cargo clippy --all-targets --all-features --workspace -- -D warnings` (warnings are errors — this gates CI)
- Aggregates: `make ci` (fmt-check + clippy + test), `make pre-commit` (fmt + clippy + test)
- Run: `./target/release/ferrous-dns --config ferrous-dns.toml`

No `rustfmt.toml` or `clippy.toml` — formatting/linting use defaults; the only enforced deviation is `-D warnings`.

## Project structure

```
ferrous-dns/
├── crates/         Cargo workspace members (Rust source)
├── tests/          integration tests & benchmarks crate (flows/, performance/, common/)
├── web/            Web UI — static HTML/CSS/JS in web/static/, served by the binary
├── migrations/     SQLite schema migrations, applied at runtime via sqlx::migrate!
├── docs/           MkDocs documentation source (own guidance in docs/CLAUDE.md)
├── site/           generated MkDocs output — do not hand-edit
├── bench/          benchmark harness & competitor configs (Pi-hole, AdGuard, unbound, …)
├── scripts/        release & version-bump scripts (release.sh, bump-version.sh)
├── docker/         container entrypoint (Dockerfile* and docker-compose.yml at repo root)
├── Cargo.toml      workspace manifest
├── Makefile        aggregate targets (make ci, make pre-commit, …)
└── ferrous-dns.toml  example/runtime config
```

### Architecture (the `crates/` workspace)

Cargo workspace (edition 2021, `resolver = "2"`) following Clean Architecture — respect the dependency direction:

- `crates/domain` — pure business logic. **Keep dependency-light: no I/O, no async runtime, no frameworks.**
- `crates/application` — use cases and ports (traits).
- `crates/infrastructure` — adapters that implement the ports: SQLite (sqlx), cache, DNS resolvers (hickory), TLS/transport (DoT/DoH/DoQ/H3). Feature flags: `dns-over-rustls`, `dns-over-https`, `dns-over-quic`, `dns-over-h3` (all default-on).
- `crates/jobs` — background jobs.
- `crates/api` — REST API (axum 0.8) + OpenAPI (utoipa).
- `crates/api-pihole` — Pi-hole v6 API compatibility layer.
- `crates/cli` — binary crate, produces the `ferrous-dns` executable.
- `tests/` — integration tests & benchmarks crate (also a workspace member).

## Gotchas

- hickory is pinned to an **alpha** (`0.26.0-alpha.1`); its API may shift between versions.
- The `release` profile uses `panic = "abort"` — release builds don't unwind, so panic-catching behaves differently than in debug.
- sqlx uses **runtime queries + `sqlx::migrate!`**, not compile-time `query!` macros. There is **no build-time `DATABASE_URL`** requirement and no `.sqlx` offline cache. Migrations live in `migrations/`.
- Error handling: return `Result`, never `panic!` on bad input.
- Committed DB artifacts (`ferrous-dns.db`, `-wal`, `-shm`) exist in the tree — don't edit or commit changes to them.
- `tests/performance/competitor_comparison.rs` is `#[ignore]`d (needs external DNS servers running) and won't run in normal `cargo test`.
- Runtime env vars: `FERROUS_CONFIG`, `FERROUS_DNS_PORT` (53), `FERROUS_WEB_PORT` (8080), `FERROUS_BIND_ADDRESS`, `FERROUS_DATABASE`, `FERROUS_LOG_LEVEL`; `RUST_LOG=debug` for debug logging.

## Repo etiquette

- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Branch naming: `feature/`, `fix/`, `docs/`, `refactor/`, `test/`.
- Releases via `./scripts/release.sh [major|minor|patch]` (runs tests + fmt + clippy, bumps versions, tags).
- Docs site (MkDocs) has its own guidance in `docs/CLAUDE.md`; public docs are written in English.

## Skills

- `/verify-ci` — run the full local CI gate (`make ci`: fmt-check + clippy `-D warnings` + tests) before marking work done or committing.
- `/sync-agents` — re-scan the project and refresh the structural sections of both AGENTS.md files when crates, folders, migrations, or feature flags change.

## Tooling

- A PostToolUse hook runs `rustfmt` on every edited `.rs` file automatically (configured in the wrapper-dir `.claudin/settings.json`, outside this repo).

To refine: `/skills` (skills), `/hooks` (hooks), `/permissions` (viewer for permission rules — edit `settings.json` directly to change them).
