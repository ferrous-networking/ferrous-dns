---
name: cache-time-counts-coalesced-followers
description: Coalesced in-flight followers were logged as cache hits timed with their upstream wait, inflating Cache Time; fixed on fix/coalesced-followers-as-upstream (followers = upstream answers + coalesced marker/icon)
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

**Status:** fixed on branch `fix/coalesced-followers-as-upstream` (2026-10-23). Viudes decided the product call: a follower counts as an upstream answer, with a marker.
- `InflightResult` carries the leader's `cache_hit`, `upstream_server` and `upstream_pool`. `to_resolution` sets `coalesced: Some(Follower)`.
- The leader drops its own receiver, and `publish_inflight` returns `receiver_count()`. A leader that had followers gets `Some(Leader)`.
- New domain enum `CoalescedRole`, the `QueryLog.coalesced` field, and the TEXT column `query_log.coalesced` (`leader`/`follower`/NULL, migration `20261023000001`). The API carries `coalesced`.
- The Query Log shows an inline `git-merge` icon (class `coalesced-icon`, tooltip via `answer-tip`) in the CLIENT cell of both roles.
- Live: 5 concurrent clients behind a 400 ms upstream. On main, Cache Time was 320 ms and Pi-hole reported CACHE 5. On the branch, Cache Time is 0.058 ms, Pi-hole reports FORWARDED 5, and one leader plus four followers carry the icon.

Related: [[cache-per-entry-refresh-timer]].
