<!--
Title convention: `type - short description` (hyphen), e.g. `feat - DNS64 AAAA synthesis for IPv6-only clients`.
Types: feat, fix, refactor, chore, docs, perf, test.
-->

## Summary

- What this PR does and why — lead with the behavior change, not the file list.
- Add sub-sections (Configuration, Resolver, Security invariant, …) when the change spans multiple areas.

## Related issues

Closes #

## Test plan

- [ ] `make ci` green (fmt-check + clippy `-D warnings` + full test suite).
- [ ] New/updated tests: `crates/<crate>/tests/...`
- [ ] Manual: <steps to reproduce / verify at runtime>

## Known follow-ups / out of scope

- Anything intentionally deferred, pre-existing behavior touched, or optional review notes.
