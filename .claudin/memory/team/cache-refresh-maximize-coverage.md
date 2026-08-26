---
name: cache-refresh-maximize-coverage
description: Optimistic refresh must renew every eligible entry ahead of expiry — never cap total refresh throughput with a fixed rate; bound concurrency instead
type: feedback
---

The cache's stated design goal is **maximum renewal coverage and maximum hit rate**: every
entry that is still being used should be renewed before it expires, so a client request
practically never falls through to upstream. Refresh throughput must therefore follow
demand. Do not introduce a fixed ceiling (queries/sec, entries/cycle, or similar) on
optimistic refresh.

**Why:** a fixed rate and a burst limit are different things, and it is easy to reach for
the first when you mean the second. Steady-state demand is `entries / cache_min_ttl`
renewals per second, so any constant rate silently defines a maximum cache size: at
`cache_min_ttl = 300`, a 4/s cap sustains only 1200 entries. Everything above that stops
being renewed, crosses the serve-stale death line at `2 x TTL`, is marked for deletion and
becomes a hard upstream miss — the exact opposite of the goal, and invisible in the metrics
that existed at the time. This was observed in production after PR #210 and fixed in
[[cache-adaptive-refresh-pacer]].

**How to apply:** to smooth a burst, bound *concurrency* (`MAX_CONCURRENT_REFRESHES = 16`
in `crates/infrastructure/src/dns/cache_maintenance.rs`) or spread the work across the
cycle interval by dividing that interval by the real backlog. Both keep instantaneous
upstream load bounded without capping the total. When a limit must drop work, make it
prioritize rather than filter — rank by what the loss costs and shed the tail — and emit a
counter plus a `warn!` so the shed is visible instead of silent. Treat any new knob whose
only sensible value is "off" as dead config and remove it.
