---
name: cache-eviction-prefix-sample-fixed-batch
description: evict_by_strategy samples only the iteration prefix (tail shards never evicted) and removes a fixed batch per pass, so inserts faster than batch/s keep the cache over max_entries; kept on purpose 2026-10-16
type: project
paths:
  - crates/infrastructure/src/dns/cache/storage.rs
---

**Symptom:** two weaknesses in capacity eviction.
- **Not a real sample.** `evict_by_strategy` scores the first `count × cache_eviction_sample_size` entries in DashMap iteration order, starting at shard 0. At the defaults that is 160k of 200k, about 80%. The documented 500k/0.05 profile scores only 40%. Entries in the tail shards are never candidates, so hot names near the front get evicted instead of cold ones at the back.
- **Fixed batch per pass.** One pass removes `max_entries × cache_batch_eviction_percentage`, however far over the cache is. If new names come in faster than one batch per pass, the cache stays above `cache_max_entries` and is held down only by entries dying at 2×TTL.

**Where:** `DnsCache::evict_by_strategy` and `evict_entries` in `storage.rs`. Also there: the unscored `evict_arbitrary_entries` branch only runs at `len <= max/2`, which the capacity check (`len >= max`) never reaches, so outside tests it is dead.

**Repro:** set `cache_max_entries = 1000` and send 200 unique names/s ([[runtime-verification-recipe]]). On 2026-10-16 the event-driven branch held at about 2,800 entries, at 100 evictions per tick. With the old 60 s job it was about 100 per minute, and main reached 17,800. At the defaults a pass is 20k, so outpacing it needs over 20k new names/s.

**Status:** open and unfiled as of 2026-10-16. The event-driven removal work ([[cache-event-driven-removal]]) runs `evict_entries` every second instead of every minute but left the rule untouched.

**Why not fixed:** Viudes's rule for that work was "same rules, only the trigger changes". The fixes change eviction behaviour, so they belong in their own PR: evict only the overshoot, sample from a rotating cursor, and drop the dead branch.
