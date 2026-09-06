<!--
Title convention: `type(scope): description` — Conventional Commits, lowercase,
written as a full sentence. CI validates the title, so a bad one fails the build
even with clean commits. See .claudin/rules/pr-titles.md.

  fix(cache): stop corrupting non-ASCII bytes in oversized cache keys
  feat(query-log): record and display the client protocol on each query

Types: feat, fix, docs, style, refactor, perf, test, chore, ci, build.
Scope is the subsystem (dns, dnssec, cache, auth, api, query-log, block-filter,
docker, config); omit it only when the change is repo-wide.

PR #219 is the worked example of everything below.
-->

## Summary

<!--
Lead with the behavior change, not the file list: what was wrong (or missing),
what it does now, and why that is the right fix. Name the symbols and paths so a
reviewer can find them.

If the change spans several areas, give each one its own `###` sub-section with a
descriptive title ("Reload on change", "Counting wildcards") rather than one long
paragraph. State the reproduction if you have one — the command you ran, the
output before, the output after.

Call out any deliberate tradeoff you accepted, in the open. A reviewer who finds
it themselves will assume you missed it.
-->

## Related issues

Closes #

## Test plan

<!--
Evidence, not intentions. Tick a box only for something you actually ran, and say
what it produced.
-->

- [ ] `make ci` green — <test count>, fmt-check and clippy `-D warnings` clean.
- [ ] New/updated tests — name the file and what each one pins down:
  - `crates/<crate>/tests/<file>.rs` — <the behavior it would catch a regression in>
- [ ] Manual, against a real build — the exact command and the exact result:
  - <e.g. `dig @127.0.0.1 -p 15353 example.com` returned `0.0.0.0` with `EDE 15 (Blocked)`>
- [ ] UI changes: driven in a browser, with a screenshot and a clean console.

## Known follow-ups / out of scope

<!--
What you deliberately did not do, and why. Pre-existing gaps you noticed but did
not widen belong here too — say what the gap was *before* this PR so nobody reads
it as a regression you introduced. An empty section is fine; a dishonest one is not.
-->

-
