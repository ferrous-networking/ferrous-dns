# PR review standards

Applies when reviewing someone else's pull request. The workflow is `/review-pr`; this is the judgment.

## Verify, don't trust

Every claim in a PR description is a hypothesis until it is reproduced in the session. That includes "make ci green", "no behavior change for X", and "matches the existing pattern" — the last one is wrong most often, because the author compared intent while the two paths differ in what they validate.

Cite `file.rs:line` for every finding. A finding without a line number is an opinion.

## Classify before you weigh

Three different things get called "a regression". Keep them apart, because only the first is a merge blocker:

- **Breaks existing behavior** — something that worked before returns a worse result now. Test: name the input, the old output, and the new one.
- **Changes behavior** — an observable difference that is neutral or an improvement, such as a wrong NXDOMAIN becoming a correct NODATA with a different cache TTL. Worth writing down, never a blocker; flag it when no test covers the new branch.
- **Pre-existing exposure widened** — a gap that already existed and whose blast radius grows. Say so explicitly, and say what the gap was *before* the PR. Holding a user-facing fix hostage to a hazard the PR did not introduce penalizes the wrong person.

## Approve with follow-up by default

`request-changes` is for something that breaks existing behavior, is unsafe to ship, or is wrong in a way the author must fix. If nothing regresses, approve and record the rest as non-blocking follow-ups, then offer them to the author for a separate PR.

A one-line fix with a real regression test that unblocks a user-facing bug ships. Scope creep dressed as review is still scope creep.

## Tone

Write to the person, not the diff. Thank them for what was actually good, be specific about it, and frame follow-ups as invitations with no expectation attached. Reviews here are read by outside contributors deciding whether to come back.
