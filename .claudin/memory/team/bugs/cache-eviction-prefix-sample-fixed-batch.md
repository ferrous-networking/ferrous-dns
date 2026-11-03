---
name: cache-eviction-prefix-sample-fixed-batch
description: evict_by_strategy sampled only the iteration prefix (tail shards never evicted) and removed a fixed batch per pass, so inserts faster than batch/s kept the cache over max_entries; fixed for #324 on fix/cache-eviction-overshoot (overshoot + headroom, rotating cursor); the same prefix bias remains in CountedDashMap::evict_if_full
type: project
paths:
  - crates/infrastructure/src/dns/cache/storage.rs
  - crates/infrastructure/src/counted_map.rs
---

**Symptom:** two weaknesses in capacity eviction.
- **Not a real sample.** `evict_by_strategy` scored the first `count × cache_eviction_sample_size` entries in DashMap iteration order, starting at shard 0. At the defaults that is 160k of 200k, about 80%. The documented 500k/0.05 profile scored only 40%. Entries in the tail shards were never candidates, so hot names near the front got evicted instead of cold ones at the back.
- **Fixed batch per pass.** One pass removed `max_entries × cache_batch_eviction_percentage`, however far over the cache was. If new names came in faster than one batch per pass, the cache stayed above `cache_max_entries`, held down only by entries dying at 2×TTL.

**Where:** `DnsCache::evict_by_strategy` and `evict_entries` in `storage.rs`. Also there: the unscored `evict_arbitrary_entries` branch only ran at `len <= max/2`. The tick's capacity check (`len >= max`) reaches it only in a race, when expiry timers empty the cache between the check and the `spawn_blocking` pass, and then it evicted live entries with no pressure.

**Repro:** set `cache_max_entries = 1000` and send 200 unique names/s ([[runtime-verification-recipe]]; the fake upstream also needs `dnssec_mode = "Off"`, or nothing is cached). On 2026-10-16, with `cache_max_ttl = 10`, the event-driven branch held at about 2,800 entries, at 100 evictions per tick. On 2026-11-03, with TTL 3600, main grew by about 100 entries/s with no plateau: 6,565 after 60 s.

**Status:** issue #324 (v1.0.0). Fixed on branch `fix/cache-eviction-overshoot` (2026-11-03): red `f173fd9f`, fix `5992d76b`, docs `8dc00932`. The review round added four commits, `903a1567`..`d7fd8fcc`. Opened as PR #360 on 2026-11-03.
- A pass removes `len − max_entries` plus `max(1, max_entries × batch)` as headroom, so it ends at `(1 − batch) × max_entries`. A pass on a cache below capacity does nothing.
- Candidates come from a window that starts at `eviction_cursor` (approximate position in iteration order) and wraps round to the front. One labelled loop walks `iter().skip(start)` and then `iter().take(start)`, so no two shard guards are ever alive at once.
- `evict_arbitrary_entries` was removed. `cache_eviction_fallback_test.rs` became `cache_eviction_deadlock_test.rs`, the same #228 guards on a full cache.
- Tests: `crates/infrastructure/tests/cache_capacity_eviction_test.rs`. The issue's second test ("the most-hit entry in the last shard survives") passes on main, because the tail is never sampled, so it was replaced by "a cold entry is evicted wherever its key lands".
- Bench `cache_maintenance/evict_pass_full_200k`: 9.79 → 12.35 ms (+25%), and 12.73 ms on the final build. That is the cost of skipping to the cursor without dashmap's `raw-api`. The pass runs at most once a second, on a blocking thread, and only on a full cache.
- Live, 200 unique names/s for 60 s, max 1000: main peaked at 6,565; the branch peaked at 1,158 and stayed at 900–1,099 under load.

**Review round (3 agents, 2026-11-03):**
- **Revisited keys.** When expiry timers remove entries during the walk, the wrap-around walk can revisit a key, so it reaches the heap twice. The pass then counted a removal that found nothing: 7–17 phantom evictions in ~480k under a threaded repro, 0 on main.
  - Fixed by counting only `remove(..).is_some()` (`63e7e9a0`). That also fixes the old over-count when a timer wins the race.
  - No deterministic red test exists for it; the repro is timing-based.
- **Deadlock guard for the second walk.** The deadlock guards never ran the walk round from the front. A third pass over windows of 3 in a map of 8 now does (`903a1567`). Breaking that walk with a `remove` fails only this test.
- **Other changes.**
  - The walk is one labelled loop (`051a2e91`).
  - The cursor doc says it is approximate.
  - The bench comment says it measures close to the longest walk. The final build is at 12.73 ms against 9.79 (+29%).

**Still open (follow-ups):**
- **A second caller.** `insert_permanent` calls `evict_entries()` inline when the cache is full (`storage.rs`), outside the worker's one-pass-at-a-time guard.
  - If an admin's local-record edit lands during a worker pass, both passes remove the overshoot plus headroom. A repro dropped a 20k cache to 16,545 instead of 18,000.
  - Main already over-evicted here: two batches.
  - The fix would be a single-flight flag in `DnsCache`.
- **No range check on `cache_batch_eviction_percentage`.** Absurd values overflow the count, and main crashes on them too.
- **Prefix bias in `CountedDashMap::evict_if_full`** (`counted_map.rs`, used by the negative and DNSSEC caches). Per insert on a full map, it checks the first 32 entries for expired ones, then removes `iter().next()`: always the front of shard 0. Negatives also leave by their own timers. DNSSEC material has none, so its tail zones keep expired keys until replaced.

**Why it waited:** Viudes's rule for the event-driven removal work was "same rules, only the trigger changes" ([[cache-event-driven-removal]]). These fixes change eviction behaviour, so they got their own PR.
