---
name: verify-skill-name-collision
description: Skill(verify) launches the bundled runtime-verification skill, not this repo's CI gate — run the gate steps directly or use /pre-pr
type: feedback
---

`.claudin/skills/verify/SKILL.md` is this repo's local CI gate (fmt-check,
clippy `-D warnings`, tests, doc tests), but a bundled skill shares the name, and
invoking `verify` through the Skill tool loads the bundled one — "build the app,
run it, drive it to the changed code", which explicitly forbids running tests.
Observed 2026-09-19.

**Why:** the two carry opposite instructions, so following the wrong one skips
the gate AGENTS.md requires before every commit.

**How to apply:** run the gate's steps directly — `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --workspace`, `cargo test --workspace --doc` (the workspace has no
doc tests, so "0 collected" is the expected result) — or invoke `/pre-pr`, whose
name does not collide and which adds `cargo audit` and the docs version check.
Save the bundled `verify` for when you really do want to run the server and watch
it: [[runtime-verification-recipe]].
