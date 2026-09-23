---
name: wildcard-local-records
description: Why wildcard local DNS records resolve above the cache instead of being stored in it, and the two pre-existing local-record bugs found while building it (PR #224, issue #223)
type: project
scope: dns/local-records
impact: structural
paths: crates/infrastructure/src/dns/resolver/local_wildcard.rs
---

Local DNS records (`[[dns.local_records]]`) are the feature users call "DNS
rewrites". Before PR #224 (2026-09-10, closing #223) a `hostname = "*"` was
accepted at every layer, written to `ferrous-dns.toml`, and installed as a
permanent cache entry under the literal key `*.example.com` — which an exact
cache lookup (`crates/infrastructure/src/dns/cache/key.rs:69-71`) can never
match. Silently dead: no error, no warning, no log line.

**Why the wildcard layer sits above the cache.** `LocalWildcardResolver`
(`crates/infrastructure/src/dns/resolver/local_wildcard.rs`) is inserted between
`FilteredResolver` and `CachedResolver`. Below the cache would be the obvious
spot — expansions would get cached and take the fast path — but
`CachedResolver::store_in_cache` has no opt-out, and an expansion of
`*.home.lan` stored under a concrete name can never be enumerated again to
invalidate when the wildcard is deleted. Tracking expansions per pattern is
unbounded (a client can query a million random subdomains). Above the cache
costs one `is_empty()` check per query and gives instant deletes. It must stay
*below* `FilteredResolver`, which can rewrite the qname
(`resolver/filters.rs:47-56`).

Three properties fall out of walking the qname upwards from its parent: the apex
is never covered (RFC 4592), the longest wildcard wins, and a name never matches
a wildcard anchored on itself. Exact-beats-wildcard comes from probing
`inner.try_cache()` before answering — exact records live in the cache as
permanent entries, so that probe *is* the exact-record lookup.

`local_dns: true` on the resolution is load-bearing, not cosmetic: the rebinding
guard returns early on it (`use_cases/dns/rebinding_guard.rs:45`), so without it
every wildcard pointing at an RFC1918 address would be blocked as a rebinding
attack.

**Wiring trap.** The PTR map and the cache preload are both gated on
`!config.dns.local_records.is_empty()` (`crates/cli/src/wiring/dns/mod.rs`), so
on a fresh install the first record added from the dashboard gets no PTR until a
restart. The wildcard index is installed unconditionally to avoid inheriting
that bug.

**Two pre-existing permanent-entry bugs, found while building this and fixed in
the same PR:**

1. Permanent entries could be evicted with no way back. `delete_cache_entry`
   called `remove_record` without checking, and the Cache Control page rendered
   Remove on every row, so deleting a local DNS record from the cache
   unpublished the name until restart. `DnsCache::clear` had the same hole
   (wiped `permanent_keys`) but has **no caller in production code** — that half
   was latent, not the "flush button" it first looked like. Now: `400` from the
   endpoint, a `local record` label instead of the button, and `clear` restores
   what it collected.
2. The TTL served for a permanent entry was the distance to its `u64::MAX`
   sentinel expiry — `dig nas.home.lan` returned ~2.5 billion seconds, on both
   the L2 and L1 paths. `insert_permanent` also discarded the record's own TTL
   for a hardcoded 365 days; it now takes a `ttl` argument.

Related: [[runtime-verification-recipe]].
