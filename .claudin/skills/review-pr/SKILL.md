---
name: review-pr
description: Full review of a GitHub PR in this repo — fetches the PR and its linked issue, checks out the branch, traces every consumer of the changed code, verifies the author's claims by actually running them, then drafts a review comment and shows it before posting. Use when the user says "review PR N", pastes a PR URL, or asks whether a PR is safe to merge.
argument-hint: [pr-number]
arguments: pr
---

Review PR $ARGUMENTS end to end. What counts as a finding, how to classify it, and when to approve rather than request changes: `.claudin/rules/pr-review.md`.

## 1. Gather

Batch these — they are independent:

1. `gh pr view $pr --json number,title,author,state,body,headRefName,baseRefName,additions,deletions,changedFiles,mergeable,url` and `gh pr view $pr --json files`
2. `gh pr view $pr --json body` and `gh pr diff $pr` with `full: true` — the default summary elides the body and the hunks you need
3. `gh pr view $pr --json comments,reviews,statusCheckRollup,commits` — don't redo work an existing review already did, and note which checks are still in flight
4. The linked issue (`Closes #N` in the body): `gh issue view N --json number,title,body,state,comments`

The issue states the symptom, the PR states the fix. Reviewing whether the second actually resolves the first is a separate question from whether the code is correct — answer both.

Then `gh pr checkout $pr` and confirm what the branch is based on (`git log --oneline -2`). A branch cut from an old `main` can pass CI and still be wrong against the current tip.

## 2. Map the blast radius

Don't trace consumers with a serial chain of Reads. Fork parallel agents (the Agent tool with no `subagent_type`) in ONE message, each with a concrete numbered question list. The split that works for resolver/cache/DNS changes:

- one fork for the **runtime path** — every read site of the changed field or function, what actually reaches the client, wire/protocol details, and whether the PR's claim about the consuming code is literally true
- one fork for **state** — caching, TTLs, persistence, background jobs, and which downstream layers now behave differently

Then read the cited lines yourself for each fork's load-bearing claim. Forks are right often enough to trust the map and wrong often enough that the finding you'd stake the review on needs your own eyes.

## 3. Verify the claims — do not take the description on trust

1. **Earn the regression test.** Revert the fix with an Edit, run the new test, and confirm it fails at the exact asserted message. Restore the line and confirm `git diff --stat` shows nothing left behind. A test that passes both ways is not a regression test.
2. **Run the suite**: `cargo test --workspace --all-features` and `cargo clippy --all-targets --all-features --workspace -- -D warnings`, or the `/verify` skill.
3. **Trap**: `cargo test ... | tail` reports *tail's* exit code, not cargo's. Never conclude "green" from a piped exit status — use the RunTests tool or read the pass/fail counts.

Every row you put in the verification table must be something you ran in this session.

## 4. Draft the comment

In this order:

1. **Opening** — thank the contributor, and name specifically what they did well (repro steps, isolated root cause, a test that fails without the fix). Say contributions are welcome.
2. **Verification table** — check on the left, result on the right, including the reverted-fix row.
3. **Does anything existing break?** — an explicit section, even when the answer is no. Name the code that makes it safe (which branch wins, which guard is untouched).
4. **Findings**, severity first, every one citing `file.rs:line`. Classify each per `.claudin/rules/pr-review.md`.
5. **Follow-ups** — marked non-blocking, each with the shape of the fix and its blast radius.
6. **Invitation** — offer the follow-ups to the author for a separate PR, explicitly with no expectation, and ask which they want so nobody files duplicate issues.
7. **Small stuff** — nits, docs, conventions, last.

If your investigation found the bug is *worse* than the author claimed, say so — it strengthens their case and belongs in the issue's record.

## 5. Show, then post

Show the full draft to the user and stop. Do not post until they say to.

When they approve: Write the body to a temp file and `gh pr review $pr --approve --body-file <path>` (or `--comment` / `--request-changes` as instructed), then delete the temp file. Never pass a long markdown body inline — backticks, `$` and apostrophes in the same text make the quoting unreliable.

Afterwards, return to the branch you started on and report anything left open: unfiled follow-up issues, checks still running.
