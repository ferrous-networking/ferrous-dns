# Internals

[Benchmarks](benchmarks.md) shows the numbers. This page documents the machinery that produces them: how packets get in and out of the kernel, what is cached where, and which of it you can actually tune.

---

## Listener: one worker per core, SO_REUSEPORT

At startup Ferrous DNS detects the number of CPU cores and spawns that many **independent** UDP sockets and TCP listeners, all bound to the same address with `SO_REUSEPORT`. The kernel hashes each incoming datagram to one socket, so workers never contend on a shared receive queue and there is no single-threaded accept loop to saturate.

Each socket is also configured with:

- `SO_REUSEADDR` and 4 MB send/receive buffers, to survive bursts without dropping datagrams.
- `SO_INCOMING_CPU`, pinning a worker's traffic to the core it runs on so packet processing stays on one cache hierarchy.
- `SO_BUSY_POLL` at 50 µs, trading a little CPU for lower wake-up latency (best-effort; ignored by kernels that do not support it).

Tokio's runtime threads are pinned round-robin to cores as well.

!!! note "Worker count is not configurable"
    There is no `workers` key. The count is always the number of detected cores. On a container with a restricted cpuset, the cpuset determines it. If you need fewer workers, restrict the cpuset.

---

## Batched syscalls: recvmmsg / sendmmsg

On Linux the UDP path reads and writes datagrams in batches of **64** using `recvmmsg` and `sendmmsg`, amortizing the syscall over up to 64 queries. All buffers and control-message storage are allocated once per worker and reused, so a batch costs no allocations.

This is selected at compile time (`#[cfg(target_os = "linux")]`), not by a feature flag or config key. On non-Linux targets the server falls back to a single-datagram loop with identical behaviour and lower throughput.

---

## Correct source address on multi-homed hosts (IP_PKTINFO)

A server bound to `0.0.0.0` on a machine with several addresses can answer from the *wrong* source IP, and clients will drop such replies. Ferrous DNS enables `IP_PKTINFO` on its UDP sockets, records the destination address of each incoming query from the control message, and writes it back as a control message on the reply — so the answer always leaves from the address the client sent to.

Only IPv4 `IP_PKTINFO` is handled today; there is no `IPV6_RECVPKTINFO` path.

---

## The cache is three things, not one

### L1 — thread-local hot cache

- **1024 entries per worker thread**, LRU, compile-time constant, not sized by any config key. Total footprint is 1024 × the number of worker threads.
- Holds **A/AAAA answers only** (`Arc<Vec<IpAddr>>`). CNAMEs, negative answers and wire-format records for other types live in L2 exclusively.
- Keys are built in a stack buffer, so a lookup under 260 bytes of key allocates nothing.
- Invalidated across threads through a global generation counter.

### L2 — the shared cache

This is the real DNS cache, and it is what the `[dns] cache_*` keys configure.

| Property | Value |
|:---------|:------|
| Capacity | `cache_max_entries`, default **200,000** |
| Structure | Sharded `DashMap`, `cache_shard_amount` shards (auto: 4 × cores, clamped to 8–256) |
| Eviction | `cache_eviction_strategy`: `hit_rate` (default), `lru`, `lfu`, `lfu-k` |
| Eviction style | Probabilistic — samples `cache_eviction_sample_size` candidates instead of scanning |
| Record types | **All of them** — A/AAAA as parsed IPs, CNAME, everything else as raw wire bytes |
| Negative answers | Separate negative cache with its own 300 s floor, deliberately outside `cache_min_ttl` / `cache_max_ttl` |
| Miss short-circuit | A bloom filter sized at 2 × capacity (1% false positives) skips the map on definite misses |

On top of that sit **optimistic refresh** (popular entries renewed before expiry, `cache_optimistic_refresh` and friends), **stale-while-revalidate** (a stale entry is served with a 2 s TTL while the refresh is queued), and **in-flight coalescing** (N concurrent misses for the same key produce exactly one upstream query).

### L0/L1 — the block decision cache

Blocking decisions have their own two-tier cache, separate from the answer cache:

| Tier | Capacity | Eviction | Scope |
|:-----|:---------|:---------|:------|
| L0 | 256 | LRU | Thread-local |
| L1 | 100,000 across 64 shards | LRU | Shared |

Entries are keyed on `(domain, group_id)` — the same domain can be blocked for one client group and allowed for another — with a 60-second TTL. L0 is invalidated by bumping a global epoch, L1 by clearing shards, so a blocklist change takes effect without walking either structure. None of it is configurable; all values are compile-time constants.

---

## Fast path for cache hits

For a cache-hit A/AAAA query, the response is built directly from wire bytes — no full DNS message construction — and queued inline for the next `sendmmsg` batch. Queries with the DNSSEC OK (DO) bit set skip the fast path and take the regular resolution route, since they need the full record set.

---

## Blocklist compilation

Enabled blocklist sources are compiled into a matcher where each domain carries a `u64` bitmask of the sources that contributed it, which is what makes "why is this blocked?" answerable without re-querying every list.

!!! warning "63 active sources maximum"
    One bit is reserved for manually added entries, leaving **63 downloaded sources**. If more than 63 sources are enabled, the 63 lowest-numbered ones are compiled and the rest are **silently skipped** — the only signal is a `WARN` line at startup and after each blocklist refresh. It is a soft cap: the UI and API will happily let you create more.

---

## Allocator and build profile

- **mimalloc** is the global allocator — measurably better than the system allocator for the many small, short-lived allocations of DNS parsing.
- Release builds use fat LTO, a single codegen unit, `panic = "abort"` and no overflow checks.

---

## What you can tune

| Knob | Where | Default |
|:-----|:------|:--------|
| Cache capacity | `[dns] cache_max_entries` | 200,000 |
| Eviction strategy | `[dns] cache_eviction_strategy` | `hit_rate` |
| Cache shards | `[dns] cache_shard_amount` | auto (4 × cores, 8–256) |
| In-flight shards | `[dns] cache_inflight_shards` | auto (2 × cores, 8–128) |
| TTL floor/ceiling | `[dns] cache_min_ttl` / `cache_max_ttl` | 0 / 86400 |
| Optimistic refresh | `[dns] cache_optimistic_refresh` and `cache_refresh_*` | on |
| Query log batching | `[database] query_log_*` | 2000-row batches, 200 ms flush |

Everything else on this page — worker count, batch size, L1 size, block decision cache, socket options — is fixed at compile time.

See [Cache Configuration](../configuration/cache.md) for the full reference of the tunable half.
