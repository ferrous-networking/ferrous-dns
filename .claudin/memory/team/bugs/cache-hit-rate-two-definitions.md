---
name: cache-hit-rate-two-definitions
description: Two cache hit rates disagree. Since #377 the Dashboard, Settings and /stats use query-log hits ÷ (hits + misses); /cache/metrics and ferrousdns_cache_hit_rate count in-memory lookups since start. Open, unfiled (2026-11-09)
type: project
paths:
  - crates/api/src/handlers/metrics.rs
  - crates/api/src/dto/cache.rs
  - crates/infrastructure/src/repositories/query_log_repository/rollup.rs
---

**Symptom:** the Prometheus gauge `ferrousdns_cache_hit_rate` and the `hit_rate` on `GET /cache/metrics` never match the hit rate shown on the Dashboard and in Settings. Before #377, Settings read `/cache/metrics`; the user report showed 89.8% on the Dashboard against 96.9% in Settings.

**Where:**
- `/stats` feeds the Dashboard, and since #377 also Settings → Performance and Cache Overview. It computes hits ÷ (hits + misses) from the query-log rollups for the window (24 h on screen). Blocked, rate-limited and filtered queries never reach the cache, so #377 left them out.
- `/cache/metrics` and the gauge (`handlers/metrics.rs` `cache_hit_rate`, "percent, since start") read the cache's in-memory counters since start. Those count lookups, not queries. Measured live on the UDP path: 2 lookups per hit and 3 per cold miss.
- In the rollups, `MinuteCounters::add` (`rollup.rs`) counts a miss as `!cache_hit && !cache_refresh && !blocked`. Local DNS answers therefore count as misses and pull the `/stats` rate down.

**Repro:** send a few hundred queries with repeats. Then compare `cache_hit_rate` on `/stats` with `hit_rate` on `/cache/metrics`, or with the gauge on `/metrics`.

**Status:** open, unfiled as of 2026-11-09. It is listed as a follow-up in PR #377 (`b2d1821d`).

**Why not fixed:** #377 only made the screens agree. The gauge and `/cache/metrics` belong to the metrics and API surface, and whether they should count queries is undecided.
