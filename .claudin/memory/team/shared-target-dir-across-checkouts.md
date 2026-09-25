---
name: shared-target-dir-across-checkouts
description: Building another checkout or worktree of this repo with the main target/ dir leaves stale workspace-crate artifacts that break the next build; use a separate CARGO_TARGET_DIR on disk (~18 GB, not tmpfs /tmp) and clean it afterwards
type: feedback
---

Never build a second checkout or worktree of ferrous-dns (for example `main`, to compare against a PR at runtime) with `CARGO_TARGET_DIR` pointing at the primary checkout's `target/`.

**Why:** cargo hashes workspace path packages by their workspace-relative path, so both trees produce artifacts with the same names. The next build in the primary checkout then trusts the other tree's rlibs. On 2026-09-23 this showed up as `E0308` against the other tree's signature for `DnsRequest::with_cookie`, even though the source was correct. Recovering needed `cargo clean -p` on every workspace package. Because that clears all profiles, it deleted about 151 GiB of cached artifacts, and release and profiling builds had to recompile the workspace crates.

**How to apply:** give the second tree its own target directory, on a real disk (`CARGO_TARGET_DIR=~/.cache/<name>/target`). It costs one cold build, but it is safe. If the primary `target/` is already polluted, run `cargo clean -p <pkg>` for each workspace package (`cargo metadata --no-deps` lists them); dependency artifacts can stay. Related: [[runtime-verification-recipe]].

**Not in the session scratchpad.** The scratchpad sits under `/tmp`, which is a 24 GB tmpfs on Viudes' machine, and one `cargo test --workspace --all-features` build of this workspace takes ~18 GB (17.7 GiB, 77.6k files, measured 2026-09-24 on the PR #251 tree). The build died mid-link with `Disk quota exceeded (os error 122)` and `ld terminated with signal 7 [Bus error]`, and neither message says "disk full". Check `df -h` first. When the comparison is done, remove the directory with `cargo clean --target-dir <dir>`; Viudes asked for that cleanup.
