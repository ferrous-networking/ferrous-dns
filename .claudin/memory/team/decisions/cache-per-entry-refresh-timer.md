---
name: cache-per-entry-refresh-timer
description: Why each cache entry arms its own refresh timer (branch fix/cache-per-entry-refresh-timer, 2026-10-12/13) instead of the 60 s scan + pacer; the per-record timer state and the one place that decides follow-ups
type: project
scope: cache/refresh
impact: structural
---

Branch `fix/cache-per-entry-refresh-timer` (2026-10-12/13, opened as a PR on 2026-10-13) replaced the 60 s refresh scan and its pacer ([[cache-adaptive-refresh-pacer]]). It came from Viudes's v0.9.22 report that hot names left the cache before their refresh.

**Why:** the scan coupled renewal to its own cadence. A candidate waited up to a cycle to be found and up to another to be drained, so a TTL short next to that window went stale before renewal, and `cache_min_ttl` had to stay ≥ 240. It also cost O(entries) every minute: 4.4 ms at 200k entries, against 29 µs/min of timer work now.

**Shape:**
- **Arming.** `DnsCache::store`/`refresh_record` arm a timer (`ScheduledRefresh`) into a sharded `TimerInbox`: 16 shards, threads assigned round-robin, never a tokio channel. The channel woke the worker on every insert and doubled `insert` (340 → 740 ns). The inbox costs +5%.
- **Worker.** `RefreshWorker` (`cache_maintenance.rs`) ticks the coarse clock itself and collects the inbox on its 1 s tick into a `BTreeMap` (`RefreshSchedule`). Order: stale repairs first, then a `BinaryHeap` ranked (hot, deadline) by `ColdThresholds`, all under the same 16 permits. Orphaned timers are swept incrementally, 16k per tick.
- **Timer state.** `HotCounters::refresh_timer` (in its padding, so `CachedRecord` stays 128 B) holds the due second of the one pending timer, or `TIMER_LAPSED` / `TIMER_PARKED` / `TIMER_CLAIMED`.
  - A timer firing for any other second is stale and spends nothing.
  - **Lapsed:** the renewal failed or was declined for good, the timer was shed, or refreshes are off. Only `compact()` arms it, so a failing upstream gets one retry per `cache_compaction_interval`, never one per hit.
  - **Parked:** the timer fired while the entry was idle. Its next L2 hit or L1 batch flush arms it.
  - **Claimed:** waiting for a permit. It holds no in-flight bit, so a stale hit can still queue its repair; `start_claimed_refresh` then stands down.
  - The review on 2026-10-13 found that the earlier `FLAG_REFRESH_ARMED` could not tell "timer pending later" from "no timer". Compaction then armed duplicates.
- **Due rule** (`refresh_due_at`): `min(threshold × ttl, max(ttl − 60, ⌈ttl/2⌉))`, at least +1 s. The ttl/2 bound only limits the 60 s lead; without it a TTL just above 60 renews every second.
- **Worth renewing** (`DnsCache::is_worth_renewing`): inside the access window and, for a TTL < 60 s, asked for since the last renewal (`last_access ≥ inserted_at`).
  - Found in the live A/B: at `cache_min_ttl = 0`, one hit kept a TTL-5 name renewing every ~4 s for the whole 2 h window (12 vs 5.3 upstream queries/s).
  - TTL ≥ 60 keeps the access-window-only rule, so no name main kept warm loses coverage.
- **Outcome.** `refresh_entry` returns `RefreshOutcome { Renewed, Declined, Removed, Kept }`. Every follow-up is decided in `RefreshWorker::follow_up` via `RefreshOrigin::retry_in`; only a `Due` origin gets one:
  - **Declined** retries at remaining − 1; if declined again, a third attempt runs at expiry, where any answer is taken, so the chain ends in ≤ 3 queries. Stopping after the second decline tripled stale hits in the live A/B (899 → 3296): a caching upstream holding the same copy offers 1 s at remaining 1. A positive answer with TTL ≤ remaining for a *live* entry is declined. Cloudflare anycast answered 560, 408 then 14 for icloud.com within 6 s, so renewals cut entries short, and this is pre-existing on main. The equal case stops an R → R/4 → … chain. Past expiry any answer is stored; otherwise TTL 0 answers looped once a second, a bug the review caught.
  - **`AllUpstreamsServfail`** retries at remaining/2. It is every server in every pool answering SERVFAIL; clients see the same SERVFAIL + EDE 22 as `TransportAllServersUnreachable`.
  - **Everything else** lapses, so compaction handles it.
  - The retry is armed before `reset_refreshing`, so compaction cannot arm a second one.
- In the same branch:
  - an Indeterminate refresh keeps the entry; only Bogus removes it, a regression from #265;
  - L1 hits are batched onto the L2 record ≤ 1×/s per thread, and a replaced L1 copy hands its batch to the caller. Before, a hot L1 name looked idle to the access window and to HitRate eviction.

**How to apply:**
- Never put a per-insert wake or a fixed rate back on this path ([[cache-refresh-maximize-coverage]]).
- A test that fires a timer must use the one the cache armed, read from the inbox via `tests/support/refresh.rs`. A hand-built `ScheduledRefresh` is stale by design.
- Keep `CachedRecord` at 128 bytes; `cache_record_layout_test.rs` pins it.
- Measure with the `cache_ops` bench (`crates/infrastructure/benches/`). A/B it against a baseline binary, run alternately in both orders: back-to-back criterion runs drift ±5% here.
