---
name: query-log-rollups-and-disk-space
description: Why a 20 GB query log got hourly rollups filled by a job (not the writer), incremental auto-vacuum and --compact-database instead of Postgres (#311, branch fix/query-log-database-growth, 2026-10-27); the exactness invariant every rollup read keeps
type: project
scope: query-log/database
impact: structural
---

**Decision:** on 2026-10-27 issue #311 ("Please support postgres": 20 GB SQLite, slow queries) went to v1.1.0, and the SQLite causes were fixed instead on `fix/query-log-database-growth`:
- **Space.** New databases use `auto_vacuum = INCREMENTAL`; the retention job gives freed pages back after each cleanup (`FreeSpaceReclaimer`, 8 MiB steps + PASSIVE checkpoint). Old files convert with `ferrous-dns --compact-database` (exclusive lock, `VACUUM INTO <db>.compact`, fsync, rename); startup warns at ≥ 64 MiB unreclaimable. Retention's first run moved from 4 h to 10 min after boot.
- **Reads.** Top domains, distinct domains and top clients read `query_log_hour_domain` / `query_log_hour_client`; the Query Log total and Pi-hole storage counts read the minute rollups. Coverage lives in the one-row `query_log_rollup_state` (`minute_since`, `hour_since`, `hour_until`, `hour_floor`).

**Why:** the file never shrank (no auto-vacuum, no VACUUM), retention never ran on servers restarted within 4 h, and every top list scanned the raw window with a table lookup per row.

**Invariant — results stay exact.** A read takes buckets only inside the coverage and raw rows everywhere else (`split_hours`: raw lead, buckets, raw tail; minute counts: raw lead + buckets), in one read transaction. Retention prunes rollups and raises the coverage **before** deleting rows. The job only holds hours closed by the current clock (60 s lag) and gives back any it holds beyond it.

**Rejected:**
- Postgres: ~180 SQLite-specific query sites, and not the cause.
- Hourly upserts in the query-log writer: measured 225k → 117k rows/s (300k rows, 3 runs per arm); per-domain upserts were the whole cost. The job leaves the writer at parity (221–229k vs 217–226k).
- A backfill migration: it would hold the first start for minutes on a large log. The job fills history newest first, 24 hours per 5-minute run.
- A covering index on `query_log`: reverses the 09-23 decision to keep wide indexes off the insert path.

**Evidence (10M client rows over 30 days, release builds, median of 5):** dashboard 24 h 0.219 → 0.024 s, 30 d 20.8 → 0.54 s; Query Log page 30 d 10.5 → 0.004 s; Pi-hole `/info/database` 1.99 → 0.003 s, top domains 0.265 → 0.058 s. Live: compaction 1.59 GB → 283 MB in 8.6 s; a retention run after it gave back 39k pages.

**How to apply:**
- A migration that rewrites `domain` or `client_ip` in `query_log` must rewrite or drop the hour buckets it touches (or lower `hour_until`), or the top lists disagree with the log.
- A new read over the rollups goes through the coverage split, never `bucket >= cutoff` alone.
- Known residual: a clock stepping back by a few minutes into an hour the job held moments earlier can leave those rows out of the top lists until retention removes them. Accepted by Viudes with the job design.
- Review on 2026-10-27 (3 agents) found the job failing BUSY under a writer, the clock-ahead hole and a Pi-hole flush blocked by the reclaim; all fixed with red tests first.
