# Build cleanup after a PR or review

One `cargo test --workspace --all-features` build leaves ~18 GB in `target/`, 12.4 GiB of it in ~315 statically linked test binaries. Cargo never deletes stale artifacts, so every branch you build adds its own copy; `target/` once reached 151 GiB. Clean up as the last step of PR work.

## When

Do it once, at the end, not between review rounds or fix iterations:

- **Your own PR**: after the final push, when the session has no fixes left for it (PR opened, review round answered, or merged).
- **A review** (`/review-pr`): after the comment is posted and you are back on the starting branch.

## What

1. In the main checkout, clean only the workspace crates, so the dependency artifacts survive:
   `cargo clean $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | "-p \(.name)"')`
   This keeps ~1.3 GB and cuts the next cold test build from ~5.5 min to ~3 min (measured 2026-11-11, `-j 8`). If `du -sh target` still shows more than 5 GB afterwards, run a full `cargo clean`. That happens when a toolchain or `Cargo.lock` bump leaves a whole stale dependency set behind, or when release builds add their own.
2. For every side target dir this session created (`CARGO_TARGET_DIR=~/.cache/<name>/target`, see `.claudin/memory/team/shared-target-dir-across-checkouts.md`), run `cargo clean --target-dir <dir>`, then `rmdir ~/.cache/<name>`.
3. Remove the agent worktrees this session created, by the exact path that was returned. Their `target/` goes with them.

Leave target dirs and worktrees from earlier sessions alone: list them with `du -sh` in the report and ask. Report the space freed with `df -h . ~/.cache` before and after; the checkout and the side target dirs can sit on different partitions.
