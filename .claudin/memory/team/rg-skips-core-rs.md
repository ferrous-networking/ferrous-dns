---
name: rg-skips-core-rs
description: ripgrep and the Grep tool silently skip crates/infrastructure/src/dns/resolver/core.rs (CoreResolver) because .gitignore has `core.*`
type: project
---

`.gitignore` lines 313-314 ignore `core` and `core.*` (core dumps). ripgrep applies
gitignore patterns even to tracked files, so a directory-wide search never sees
`crates/infrastructure/src/dns/resolver/core.rs` — the `CoreResolver`, which holds the
`local_domain` / `local_dns_server` path and one of the `DomainError::NxDomain`
producers. Found 2026-10-21 when a search for every NxDomain producer came back
without it.

**Why:** an "every call site" search that misses CoreResolver gives a wrong answer
with no hint that a file was skipped.

**How to apply:** pass `no_ignore: true` to Grep (or `rg --no-ignore`) when tracing
anything through the resolver chain, or search `core.rs` by path.
