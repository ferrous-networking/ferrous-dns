---
name: cache-eviction-random-branch-deadlock
description: A dashmap Iter holds the shard's read guard — collect keys into a let-statement before removing, or the thread deadlocks on itself (issue #228, fixed 2026-09-19)
type: project
paths: crates/infrastructure/src/dns/cache/storage.rs
---

`DashMap::iter()` returns an `Iter` that holds the `RwLockReadGuard` of the
shard it is currently walking. `remove()` wants that same shard's *write* guard,
and `parking_lot`'s `RawRwLock` is not reentrant, so removing while the iterator
is alive blocks the thread forever.

Dropping the `RefMulti` does not help — the guard belongs to the `Iter`. And on
edition 2021 (workspace-wide) the temporary in an `if let` / `match` scrutinee
lives until the end of the block, so this deadlocks:

```rust
if let Some(entry) = self.cache.iter().next() {
    let key = entry.key().clone();
    drop(entry);              // drops the RefMulti, NOT the Iter
    self.cache.remove(&key);  // blocks forever
}
```

The safe shape ends the statement — which drops the `Iter` — before removing:

```rust
let keys: Vec<CacheKey> = self.cache.iter().filter(..).map(..).take(n).collect();
for key in &keys { self.cache.remove(key); }
```

Correct precedents already in the tree: `negative_cache.rs:89-98` and `:100-103`,
`dnssec/cache/storage.rs:160-174`. Read-only iterations (`rotate_bloom`,
`get_refresh_candidates`, `listing.rs`) are fine, and `evict_by_strategy`
collects snapshots in a `for` that ends before any removal.

**History.** `DnsCache::evict_random_entry` had the bug — found 2026-09-19 while
reviewing PR #227, filed as issue #228, fixed the same day by PR #229 on branch
`fix/cache-eviction-deadlock` (26d14ea commits the test red, cf278e4 the fix).
The function is now `evict_arbitrary_entries(count)`
(`crates/infrastructure/src/dns/cache/storage.rs:730`): one scan per cycle,
skipping permanent and marked-for-deletion entries, counting only real removals.

**Skipping permanent entries is load-bearing, not polish.** No eviction path
cleans `permanent_records`, so dropping a local DNS record from the backing map
leaves the ownership index claiming a name the map no longer holds — exactly the
wrong NODATA of [[local-record-exact-nodata]]. See also
[[wildcard-local-records]].

**Left unfixed, worth a follow-up:** `use_probabilistic_eviction` is hardcoded
`true` (`storage.rs:156`) and never read from config, so the unscored branch only
ever runs at `len <= max_entries / 2` — after the pressure has passed, where
evicting live entries buys nothing. Either drop the branch together with the dead
flag, or make it an early return — both are written down on PR #229 as
out-of-scope follow-ups. Separately, no eviction path calls
`l1_clear()`, so a thread-local L1 copy keeps serving an evicted record until its
own expiry. How the branch is pinned in tests:
[[deadlock-tests-need-timeout-guard]].
