---
name: cache-time-counts-coalesced-followers
description: Dashboard "Cache Time" (avg_cache_time_ms) counts coalesced in-flight followers as cache hits, timed with their whole upstream wait; real hits are ~1.5 µs
type: project
paths:
  - crates/infrastructure/src/dns/resolver/cache_layer.rs
  - crates/application/src/use_cases/dns/handle_dns_query.rs
---

**Symptom:** the dashboard shows a "Cache Time" in milliseconds (1.6 ms on Viudes's v0.9.22 install). Real cache hits take microseconds: the live A/B on 2026-10-12 measured an average of 1.5 µs over 46k hits.

**Where:**
- `InflightResult::to_resolution` (`cache_layer.rs:28-31`) sets `cache_hit: true`.
- A query that joined another query's in-flight upstream fetch is a coalesced follower (`resolve_as_follower`). It comes back with that flag and is logged with `cache_hit: resolution.cache_hit` (`handle_dns_query.rs:903`). The logged `response_time_us` covers the follower's whole wait for the leader's upstream query.
- `avg_cache_time_ms` is the mean of `response_time_us` over `cache_hit` rows (`query_log_repository/rollup.rs:115-121`). A handful of followers waiting 100–300 ms on DoH is enough to dominate it. Note the `query_log.response_time_ms` column actually holds µs.
- The same flag also inflates "Cache Hits" and the "Cache" slice of Query Source by the followers.

**Not reproduced under the A/B harness:** it sends one query per name at a time, so it creates no followers. The hypothesis comes from code reading only. Confirm it by firing 20 concurrent queries for a fresh name and reading `cache_hit` / `response_time_ms` in `query_log`.

**Status:** open, unfiled, found 2026-10-12. Viudes was told about it. Fixing it changes what the dashboard counts as a cache hit, so it is a product decision for the maintainer, not a speed fix. Related: [[cache-per-entry-refresh-timer]].
