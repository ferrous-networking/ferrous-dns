---
name: blocklist-download-timeout-and-list-size
description: Issue #248 — 30s total fetch timeout dropped large blocklists; every edit re-downloaded every list; RAM cost of HaGeZi lists; wildcard/ URLs missed apexes
type: project
---

Issue #248 (2026-09-24, Nlwilkins93, Raspberry Pi 3 in Docker): "blocklists not syncing" came back after #216 was fixed. Fixed on branch `fix/blocklist-download-timeout` (2026-09-25), which is not merged yet.

**Symptom:** Sync returns 202, the server uses almost no CPU for 30s, the reload logs `completed`, and Last Sync never moves.

**Cause 1: the download timeout.** `reqwest` had a 30s timeout covering the whole transfer, **body included**. HaGeZi TIF is 44 MB, so it needs a sustained ~12 Mbit/s. At 1 MiB/s the download was cut at 71%, and the log said `error decoding response body` with no mention of the timeout. The fix lives in `block_filter/download.rs` (`ListDownloader`):

- connect timeout 10s
- `read_timeout` 30s, which resets on every chunk (stall detection)
- total cap 5 min
- the log says `timed out after Ns`

**Cause 2: every rebuild re-downloaded every list.** This included rebuilds triggered by a managed-domain or regex edit. A failed fetch dropped that list from the index, so an edit on a flaky link silently unblocked the whole list. Now the engine holds each list's text (`BuildState.lists`, keyed by URL). `reload()` reuses the held copies. `refresh_lists()` downloads everything again; it is called by Sync, the daily job, and the Pi-hole gravity action. A failed download keeps the held copy.

**Testing gotcha:** a `start_paused` tokio test with real loopback sockets auto-advances straight to reqwest's timeout while I/O is still in flight. A 10 ms ticker task keeps the clock stepping; see `crates/infrastructure/tests/blocklist_download_test.rs`. Tests that touch sqlx cannot use a paused clock at all.

**RAM, adblock format, one list, 64-bit build on the branch.** "Loaded" is measured after mimalloc's purge delay of about 5s. Read RSS earlier and it looks ~2x higher.

| List | Loaded | Sync peak |
|---|---|---|
| Pro | ~100 MB | ~175 MB |
| tif.mini | ~85 MB | ~140 MB |
| tif.medium | ~195 MB | ~405 MB |
| tif (full) | ~510 MB | ~1.1 GB |

- A 1 GB Pi 3 cannot sync the full TIF.
- Holding the list text costs about the file size (~45 MB for TIF).

**Docs:** the `wildcard/` HaGeZi URLs that #216 put in the docs block subdomains only. `*.x` parses as `Wildcard` (`configuration/blocking.md` documents that on purpose), so every apex resolved. The docs now link `adblock/…`, whose `||x^` lines cover the apex and its subdomains. See [[issue-216-blocklist-sync]].

**Still open:** the UI swallows sync failures. `dns-filter.js:158` polls for 60s and then stops silently, so the only signal is Last Sync not moving, plus the server log.
