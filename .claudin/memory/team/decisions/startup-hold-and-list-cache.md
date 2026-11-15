---
name: startup-hold-and-list-cache
description: Issue 365 — no port (DNS or web) opens until the block filter's first build ends, capped at 30 s; each list download is kept in lists/ beside the database and a start compiles from it, then re-downloads in the background; why the web waits too and why there is no config key
type: project
scope: block-filter, cli startup
impact: functional
---

**Decision (2026-11-12, issue #365, branch `fix/startup-filter-window`):** a start opens no listener until the block index is in force, and every list download is kept on disk so the next start compiles without the network. Viudes picked each option below from the plan `.claudin/plans/glistening-brewing-mist.md`.
- **Gate:** `main.rs` waits on `StartupBuild::wait(STARTUP_HOLD_LIMIT)` right before the first listener spawn. UDP/TCP, DoT, DoQ, DoH, the web UI, `/health`, `/metrics` and web-port DoH then come up together. `health.rs`, `doh.rs` and `start_dns_server` did not change. During the hold the web port refuses connections, so `--healthcheck` exits 1.
- **Limit:** 30 s, a `cli` constant. Past it the ports open, `Blocklists not compiled after 30 s; …` is logged at WARN, and queries go unfiltered until the build ends. The hold also applies with `[blocking] enabled = false`, since manual allow/deny is tier 1.
- **Shutdown:** the wait runs in a `select!` with the pinned `shutdown` future, so a SIGTERM during the hold still closes the database.
- **List cache:** `ListCache` (`block_filter/list_cache.rs`) lives at `<dir of [database] path>/lists/`, with no config key. Files are named `<sha256(url)>.txt` and written to a temp file, then renamed. `fetch_lists` treats a disk copy like the held one: `ReuseHeld` reuses it, and a failed `Redownload` keeps it. Every successful download is written. Every build prunes the copies no source uses, and touches only names of that pattern. Any I/O error is a WARN and never fails a build.
- **Startup re-download:** when the cache held copies as the start began, a `Redownload` runs right after the first build. A first start skips it, because it has just downloaded everything.

**Why:** answers given before the first build were never filtered, manual denies included, and `/health` already said 200 by then. Every start also downloaded every list, so a slow link widened the window and a list host that was down at start took its list out until the daily sync. Waiting fixes the first problem, and the copies make that wait short (compile only) and immune to list hosts. The per-start re-download stays because every start refreshed the lists before, and [[upgrades-keep-existing-behaviour]] keeps that.

**What changes for a teammate:**
- `BlockFilterEngine::new` keeps its old contract: it returns at once and has no cache. It has 182 test call sites, and `blocklist_source_sync_timestamp_test.rs` relies on `new` returning mid-download. Production calls `BlockFilterEngine::start(.., ListCache) -> (engine, StartupBuild)`.
- Anything new that per-query policy depends on must load before `main.rs`'s wait, as SafeSearch and malware exemptions already do (they are awaited in `Repositories::new`). Otherwise it needs its own readiness handle joined to the wait.
- The C2 IP feeds (`response_ip_filter/detector.rs`) still load in the background after a start, so the same window remains for them. They were left out of scope; an issue is to be drafted.

**Rejected:**
- **Holding only the DNS ports**, with the web up at once and `/health` at 503: DoH on the web port would need its own 503 gate, and the four spawn sites would move into tasks.
- **Binding at once and answering REFUSED + EDE 14 until ready:** that adds a response category to the query log and the rcode counters, and `/health` would need a second condition.
- **Holding inside `BlockFilterEngine::new`:** it breaks the engine's contract and its tests.
- **A `[blocking] list_cache_dir` or `startup_wait_secs` key:** more surface with no known need. The directory beside the DB is writable wherever the WAL is.
- **Keeping the list text in SQLite:** the DB grows by the lists' size, and every sync churns the WAL.
- **No re-download at start:** the daily job's timer resets on every start (`blocklist_sync.rs`), so a host that restarts daily would never refresh.

**Evidence:** live run on 2026-11-12, release builds, i9-9900KF, a UDP probe every 10 ms from the spawn.

| Case | main | branch |
|---|---|---|
| HaGeZi Pro from GitHub, restart | first answer at 0.02–0.05 s, unfiltered; 29–32 unfiltered answers; in force at 0.32–0.36 s | first answer at 0.13–0.19 s, filtered; 0 unfiltered |
| 1M entries from a local host, restart | 35–42 unfiltered answers; in force at 0.38–0.45 s | first answer at 0.32–0.34 s, filtered |
| List host failing at restart | all 391 answers unfiltered over 4 s | all filtered |
| First start without copies, HaGeZi Pro | — | first answer at 0.32 s, filtered |
| Host trickling bytes, no copies | — | ports open at 30.06 s with the WARN; unfiltered after |
| SIGTERM during the hold | — | exits in 3 ms, code 0; no `-wal` left |

The copies take 5 MB for HaGeZi Pro and 31 MB for 1M hosts entries. Pre-existing and not widened: on a host whose own resolver is ferrous-dns, the startup download can run before the DNS bind and fail. Before this change that cost the list until the daily sync. Now a kept copy stays in force, but a first start on such a host still needs another resolver.
