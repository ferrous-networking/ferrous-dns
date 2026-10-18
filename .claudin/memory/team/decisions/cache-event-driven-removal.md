---
name: cache-event-driven-removal
description: Why the cache eviction and compaction jobs became events on the refresh worker (branch fix/cache-event-driven-removal, 2026-10-16) — same rules, new trigger; the at-least-one-timer invariant, the lossless inbox it needs, and the review-found holes
type: project
scope: cache/maintenance
impact: structural
---

**Decision:** on 2026-10-16 (branch `fix/cache-event-driven-removal`, not yet a PR) the 60 s eviction job and the `cache_compaction_interval` compaction job were replaced by events on the refresh worker of [[cache-per-entry-refresh-timer]]. Viudes's rule: **the rules stay the same, only the trigger changes from job to event.**

**Why:** compaction left dead entries in memory, in the slot count and in `cache_size` for up to 300–600 s, and its `retain` write-locked every shard on each pass. Eviction reacted up to 60 s late.

**Shape:**
- **Invariant:** every non-permanent entry always has at least one pending timer: its renewal, its retry, or its expiry. So no pass looks for dead entries. Extra timers are harmless, because what a timer does is read from the record when it fires. A claimed renewal waiting for a permit holds no timer; the worker removes it itself if it dies in the queue (`give_up_dead_claims`).
- **Ownership.** The `DnsCache` owns the `TimerInbox` (`timer_inbox()`) from construction. `renew_ahead` and `retry_lapsed_after_secs` are `DnsCacheConfig` fields, filled from `cache_optimistic_refresh` and `cache_compaction_interval`. Only the stale repair queue is wired later (`set_stale_repairs`).
- **Expiry.** A fired timer that finds its entry dead (past `refresh_deadline_secs`, the end of the stale grace) or marked removes it (`DnsCache::remove_dead`), in `claim_due_refresh` and `start_claimed_refresh`. "Dead" is read from the record, so stale or duplicate timers are harmless.
  - Parking an idle entry arms its expiry timer.
  - With refresh off, or TTL 0, the store arms the expiry timer instead of a renewal.
  - Negative entries arm a `TimerKind::NegativeExpiry`.
- **Failed renewal** with no retry of its own: `rearm_lapsed` arms the next try at `min(now + cache_compaction_interval, deadline)`. This is the old compaction rule, one retry per interval and never one per hit. The key keeps its name; it now means only that.
  - A claim that stands down for a running serve-stale repair (`start_claimed_refresh` returns `false`) also calls `rearm_lapsed`. The repair may already be past its own re-arm.
- **Capacity.** On each 1 s tick the worker checks `is_over_capacity()` and, if full, runs the same `evict_entries` (same batch %, strategy and sampling) in `spawn_blocking`. A kept `JoinHandle` stops passes from stacking. Bloom rotation runs on the same tick with the same period as before.
- **Lossless inbox.** `TimerInbox::push` never refuses: a lost timer would leave an entry that is never renewed nor removed, since nothing sweeps any more. `optimistic_refresh_shed` now counts only "died waiting for a permit".
- **Orphan sweep** covers the negative lane too (`SweepFrom`, `holds_negative`). Without that, an NXDOMAIN flood piles up timers for negatives already evicted by `evict_if_full`: 0.7 GB+ at 5k unique NXDOMAIN/s with SOA TTL 3600.
- **Deleted:** `CacheMaintenanceJob`, `CacheMaintenancePort`, `compaction.rs`. `compactions` now counts entries removed by their timer.

**Rejected:**
- A safety-net sweep inside bloom rotation that keeps the bounded inbox. It was compaction in disguise, on a path that almost never runs.
- A per-insert size counter to detect a full cache. `len()` once a tick costs microseconds and keeps the insert path untouched.
- Evicting only the overshoot with a rotating sampling cursor, and removing `cache_batch_eviction_percentage`. Both change the rules; they are follow-ups. Today's sample is the iteration prefix (`storage.rs` `evict_by_strategy`), about 80% of the cache at the defaults.

**Evidence (2026-10-16, commits `ff0d248f` red, `fda3fcfe` fix):**
- Bench `cache_ops`, A/B against main in both orders: `insert` 341/343 ns on main and 356/339 ns on the branch, so noise. With refresh off, an insert now arms its expiry: 321/328 → 349/346 ns (+7%). Removing 10k dead entries out of 200k costs 2.56/2.71 ms of timer firings, against 2.98/2.90 ms for one `compact()` pass. The pass costs O(200k) however few entries died.
- Live, main and branch side by side: `cache_max_entries = 1000`, `cache_max_ttl = 10`, 50 unique names/s for 150 s. Main reached 7,300 entries and kept them all after the load stopped, with no compaction in 300 s. The branch stayed at ≤ 1,000 and was empty about 25 s after the load stopped.
- At 200/s the branch held at about 2,800. The unchanged rule evicts 100 per pass, now once a second instead of once a minute; main reached 17,800. At the defaults one pass is 20k, so outpacing it takes over 20k new names/s.
- `RssAnon` after the 200/s run: 53.8 MB on main, 44.6 MB on the branch. `VmRSS` misleads here: a DB on tmpfs counts as `RssShmem`.

**How to apply:**
- Any new path that stores, renews or parks an entry must leave it with a pending timer.
- Never make the inbox refuse a timer again without bringing back a sweep.
- A new timer lane must be swept too, or its orphans grow with the insert rate.
- Review on 2026-10-16 (3 agents: elegance, standards, bugs) found the stand-down hole, the dead-claim hole and the unswept negative lane. All three are fixed, each with a test that fails without its fix.
- Plan: `.claudin/plans/cuddly-waddling-matsumoto.md`.
