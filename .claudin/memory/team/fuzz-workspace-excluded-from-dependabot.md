---
name: fuzz-workspace-excluded-from-dependabot
description: fuzz/ is a separate Cargo workspace Dependabot never updates, so any version pinned in both it and the root manifest breaks every dependency-group bump
type: project
---

`fuzz/Cargo.toml` declares its own `[workspace]` (it needs nightly + libFuzzer,
while the rest of the repo runs on stable), and `fuzz/Cargo.lock` is gitignored.
Dependabot only sees the root workspace, so nothing in the fuzz manifest is ever
bumped automatically.

That bit on PR #221 (2026-09-07): the group bump moved the workspace pin to
`hickory-proto = "=0.26.2"` while `fuzz/Cargo.toml` still said `"=0.26.1"`.
Because the fuzz crate also depends on `ferrous-dns-infrastructure` by path,
Cargo saw two irreconcilable exact requirements and all five fuzz targets failed
to build with "failed to select a version for `hickory-proto`". Since
`fuzz-short` gates the `CI Success` job (`.github/workflows/ci.yml:409`), the
whole PR went red even though fmt, clippy, tests, build and audit were green.

**Why:** an exact pin duplicated across two independently resolved workspaces
has to be updated in two places, and only one of them has a bot watching it.

Fixed and merged with PR #221 on 2026-09-07: `fuzz/Cargo.toml:18` now reads
`hickory-proto = "0.26"` and carries a comment saying it must stay a range.

**How to apply:** in `fuzz/Cargo.toml`, express shared dependencies as ranges
(`hickory-proto = "0.26"`) and let the path dependency on the workspace crate
drive the exact version — Cargo unifies them. When a Dependabot PR fails only in
the fuzz jobs, check for a stale duplicate pin there before suspecting a real
crash. Related: [[runtime-verification-recipe]].
