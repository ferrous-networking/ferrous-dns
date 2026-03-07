# Performance

Ferrous DNS is engineered from the ground up for throughput. Every component in the query path was designed with latency and allocation as first-class constraints — not afterthoughts.

This page explains how the system achieves its numbers, layer by layer.

---

## The Hot Path

Every DNS query traverses this sequence. The goal: respond in microseconds when cached, in milliseconds when not.

```
UDP packet received
        │
        ▼
  Bloom filter check          ~10–15ns   ← guaranteed misses skip everything
        │ possible hit
        ▼
  L1 cache lookup             ~1–3µs     ← thread-local, zero locks
        │ miss
        ▼
  L2 cache lookup             ~10–20µs   ← sharded DashMap, per-shard lock
        │ miss
        ▼
  In-flight map check         ~200ns     ← is someone already fetching this?
        │ nobody fetching
        ▼
  Upstream query              ~1–50ms    ← DoH / DoT / DoQ / UDP
        │
        ▼
  Write to L2 + L1
        │
        ▼
  Send UDP response
```

Nothing in this path allocates on the heap for cache hits. No global locks. No syscalls for timing. Every micro-optimization is intentional.

---

## L1/L2 Hierarchical Cache

### L1 — Thread-Local, Lock-Free

Each Tokio worker thread has its own private L1 cache stored in thread-local storage. Because it is private to the thread, there is zero synchronization overhead.

```rust
thread_local! {
    static L1: RefCell<LruCache<CacheKey, CachedRecord>> = RefCell::new(...);
}
```

- No mutex, no atomic CAS, no contention — just a direct memory access
- Holds the hottest ~100–500 entries per thread
- L1 hit overhead: ~1–3µs P99

### L2 — Sharded DashMap

L2 is a shared cache backed by `DashMap` with `FxBuildHasher`. Instead of a single global lock, DashMap splits into independent shards (default: 4× CPU core count, rounded to the next power of two).

```
16-core machine → 64 shards, each with its own RwLock

Query "google.com" → hash → shard #17 → lock shard #17 only
Query "reddit.com" → hash → shard #31 → lock shard #31 only
                                         ↑ never blocks each other
```

Under real-world load with hundreds of distinct active domains, shard contention is effectively zero.

- Capacity: up to 200,000 entries (configurable)
- L2 hit overhead: ~10–20µs P99
- Hash function: `FxBuildHasher` — 3x faster than Rust's `DefaultHasher` for short strings

### Why Two Levels?

L1 absorbs the hottest queries (top ~0.1% of domains queried thousands of times per minute) without touching shared memory at all. L2 handles the long tail. Together they keep the cache hit rate above 95% for typical networks.

---

## Bloom Filter for Negative Lookups

A significant fraction of DNS queries hit domains that are simply not in the blocklist. Without a Bloom filter, each such query would trigger a full blocklist lookup — an O(n) regex scan or hash table lookup across potentially millions of entries.

The Bloom filter answers one question in ~10ns: **"Is this domain definitely not in the blocklist?"**

```
Query: "example.com"
         │
         ▼
   Bloom filter:
   "Is this in the filter?" → NO  → skip all blocklist checks instantly (~10ns total)
                            → YES → run full blocklist lookup (possible match)
```

- False negatives are impossible — a "no" answer is guaranteed correct
- False positive rate is kept very low
- Backed by `AtomicBloom` — concurrent-safe with no locking
- Cost: ~10–15ns per lookup, regardless of blocklist size

For the ~99% of queries hitting common non-blocked domains, the entire blocklist engine costs only 10–15ns per query.

---

## In-Flight Coalescing (Cache Stampede Prevention)

Without coalescing, a cache miss for a popular domain under high load triggers dozens of simultaneous upstream requests. Imagine 50 clients querying `api.github.com` at the moment the cache entry expires:

**Without coalescing:**
```
Client 1  → cache miss → upstream request
Client 2  → cache miss → upstream request  ← 50 redundant upstream requests
Client 3  → cache miss → upstream request
...
Client 50 → cache miss → upstream request
```

**With coalescing:**
```
Client 1  → cache miss → becomes "leader" → sends 1 upstream request
Client 2  → cache miss → sees in-flight entry → waits on channel
Client 3  → cache miss → sees in-flight entry → waits on channel
...
Client 50 → upstream responds → all 50 clients receive the answer simultaneously
```

The first task to see a cache miss becomes the leader and starts the upstream request. All subsequent requests for the same domain subscribe to a `tokio::watch` channel and receive the response the moment it arrives — at zero additional upstream cost.

The `InflightLeaderGuard` uses Rust's RAII (`Drop`) to guarantee the in-flight entry is always cleaned up, even if the upstream request fails or the task is cancelled:

```rust
impl Drop for InflightLeaderGuard {
    fn drop(&mut self) {
        if !self.defused.get() {
            // Notify all waiters that the upstream request failed
            if let Some((_, tx)) = self.inflight.remove(&self.key) {
                let _ = tx.send(None);
            }
        }
    }
}
```

Under load with many clients hitting the same popular domain, this eliminates the thundering-herd problem entirely and reduces upstream traffic by orders of magnitude.

---

## Optimistic Prefetch (Background Refresh)

When a popular cache entry's TTL drops below a configurable threshold (default: 75% consumed), a background task proactively refreshes it **before it expires**.

```
Entry TTL: 3600s

 0s ─────────────────────────────────── 3600s
                   ▲                       │
                   │                   Would expire
          Background refresh          (never reached —
          triggered at 2700s           already refreshed)
          (75% of TTL consumed)
```

Clients continue receiving cached responses with zero wait while the background task fetches a fresh answer. The entry is never cold for active domains.

Eligibility criteria (all must be met):

| Criterion | Config key | Default |
|:----------|:-----------|:--------|
| Minimum total hits | `cache_min_frequency` | 10 |
| Minimum hits per minute | `cache_min_hit_rate` | 2.0 |
| Last accessed within | `cache_access_window_secs` | 43200 (12h) |
| Remaining TTL fraction below | `cache_refresh_threshold` | 0.75 |

This keeps the effective hit rate close to 100% for actively-used domains as their TTLs cycle naturally.

---

## LFU-K Eviction with Sliding Window

When the cache reaches capacity, an eviction policy decides which entries to remove. Simple LRU can discard a domain queried 10,000 times that happened to be quiet for the last two minutes — replaced by one queried twice a minute ago.

Ferrous DNS uses **LFU-K**: the K most recent access timestamps are tracked per entry and used to compute a sliding-window frequency score:

```
Score = accesses in the last K timestamps / time span of those K accesses
```

This gives weight to **sustained, frequent access** rather than historical patterns. A domain popular 6 hours ago but idle since scores lower than one queried 5 times in the last minute.

Three eviction strategies are available:

| Strategy | When to use |
|:---------|:------------|
| `hit_rate` (default) | Mixed workloads — preserves the most actively queried entries |
| `lfu` | Stable workloads with predictable query distribution |
| `lru` | Bursty workloads with strong temporal locality |

---

## Zero-Allocation Hot Path

Heap allocations in the hot path are the primary cause of GC pause spikes in Go-based DNS servers (Blocky, AdGuard Home). Rust eliminates GC entirely, but heap allocations still have measurable cost at scale.

Ferrous DNS enforces a strict no-allocation policy on the cache hit path:

**`Arc<str>` instead of `String`**

Domain names are stored as `Arc<str>`. Cloning is a single atomic increment — no allocation, no copy:

```rust
// One allocation when the Arc is first created (on cache write)
let domain: Arc<str> = Arc::from("api.github.com");

// All subsequent clones: ~1ns, no heap
let domain2 = domain.clone();
```

**`SmallVec` for DNS record sets**

Most DNS responses contain 1–4 records. `SmallVec<[T; 4]>` stores up to 4 elements on the stack, falling back to heap only for larger sets — zero heap allocation for the common case.

**`eq_ignore_ascii_case` for case-insensitive comparison**

DNS names are case-insensitive. The naive approach allocates:

```rust
domain.to_lowercase() == other.to_lowercase()  // two allocations — forbidden in hot path
```

Ferrous DNS compares byte-by-byte without allocating:

```rust
domain.eq_ignore_ascii_case(other)  // zero allocation
```

**`FxBuildHasher` for DashMap**

The default Rust hasher (SipHash) is designed for hash-flooding resistance, not speed. `FxBuildHasher` is 3x faster for short strings like domain names.

---

## TSC Timer — ~1–5ns Hot Path Timing

Measuring cache hit latency with `Instant::now()` calls `clock_gettime(CLOCK_MONOTONIC)`, which costs ~20ns per call on x86_64. For a ~1µs operation that is 2% overhead per measurement.

Ferrous DNS reads the CPU's timestamp counter directly via the `RDTSC` instruction:

```rust
// SAFETY: `_rdtsc` is available on all x86_64 CPUs.
// No memory is accessed — reads hardware registers only.
#[inline(always)]
pub fn now() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}
```

`RDTSC` costs ~1–5ns — roughly 4–20x cheaper than a syscall. On non-x86_64 platforms, Ferrous DNS falls back to `CLOCK_MONOTONIC_COARSE` via the kernel vDSO (~10–15ns, no syscall).

---

## Async Query Log Pipeline

Logging every DNS query to SQLite without blocking the resolver requires a carefully designed pipeline. The DNS handler never waits for disk I/O.

```
DNS handler (hot path)
        │
        │  try_send()  ← non-blocking; drops entry if channel is full
        ▼
  Async channel  (10k–200k capacity)
        │
        │  batch read every 200ms (up to 2,000 entries per cycle)
        ▼
  Background flush task
        │
        │  single INSERT transaction per batch
        ▼
  SQLite (WAL mode)
```

Batching is critical: a single transaction with 2,000 rows is ~100x faster than 2,000 individual transactions. At very high query rates, `query_log_sample_rate` lets you log 1 in N queries to cap write volume without losing visibility.

---

## mimalloc — System Allocator Replacement

Rust's default allocator delegates to the system `malloc`, which is general-purpose but not optimized for high-throughput server patterns. Ferrous DNS replaces it with Microsoft's `mimalloc`:

- 2–3x faster than glibc malloc for small, short-lived allocations
- Per-thread free lists minimize cross-thread contention
- Reduces long-term fragmentation under sustained server load

```rust
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

---

## Parallel Upstream Strategy

On a cache miss, Ferrous DNS queries multiple upstream servers simultaneously and returns the fastest response:

```
Cache miss for "example.com"
         │
         ├──► DoQ  dns.adguard-dns.com  responds in  8ms
         ├──► DoH  cloudflare-dns.com   responds in 12ms  ← discarded
         └──► DoH  dns.google           responds in  6ms  ← returned

Client receives the answer in 6ms instead of waiting for the slowest upstream
```

This eliminates the tail-latency risk of any single upstream being momentarily slow. Upstream health is monitored continuously and unhealthy servers are excluded automatically.

---

## socket2 UDP Buffer Tuning

The OS UDP receive buffer determines how many packets the kernel queues before the application processes them. With default buffer sizes, large query bursts overflow the kernel queue and are dropped silently.

Ferrous DNS sets enlarged socket buffers at startup via `socket2`:

```rust
socket.set_recv_buffer_size(8 * 1024 * 1024)?;  // 8 MB receive buffer
socket.set_send_buffer_size(8 * 1024 * 1024)?;  // 8 MB send buffer
```

This directly improves the "queries lost" metric under peak load.

---

## Production Build

For maximum performance, always build with native CPU optimizations:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

This enables AVX2/SSE4 vectorized string operations, CPU-specific branch prediction, and proper inlining of intrinsics like `RDTSC`. The gap between a generic `--release` build and a `target-cpu=native` build is measurable in the hashing and comparison code.

---

## Summary

| Optimization | Benefit |
|:-------------|:--------|
| L1 thread-local cache | Lock-free hits, ~1–3µs P99 |
| L2 sharded DashMap + FxBuildHasher | Near-zero contention, ~10–20µs P99 |
| Bloom filter | Negative blocklist lookups in ~10ns |
| In-flight coalescing | N identical cache-miss queries → 1 upstream request |
| Optimistic prefetch | Hot entries never expire; near-100% hit rate |
| LFU-K eviction | Preserves most-active entries under memory pressure |
| `Arc<str>` + `SmallVec` + `eq_ignore_ascii_case` | Zero heap allocations on cache hit path |
| TSC timer (RDTSC) | Hot-path timing at ~1–5ns vs ~20ns syscall |
| Async query log pipeline | Query logging never blocks the resolver |
| mimalloc | 2–3x faster allocation than system malloc |
| Parallel upstream strategy | Lowest cache-miss latency, transparent failover |
| socket2 UDP buffer tuning | Absorbs large bursts without packet loss |

---

## Benchmark Results

> **Host:** Intel Core i9-9900KF @ 3.60GHz | 16 cores / 46 GB RAM | Arch Linux | Kernel 6.12.75-1-lts
> **Tool:** dnsperf 2.14.0 | 60s per server | 10 concurrent clients | 187 domains (A, AAAA, MX, TXT, NS)
>
> **Docker config (identical for all servers):**
>
> | Setting | Value |
> |:--------|:------|
> | CPUs | `cpuset: 0-15` — 16 cores |
> | Network | host mode |
> | Log level | info |
> | Cache | enabled |
> | Rate limiting | disabled |
> | Upstreams | plain UDP `8.8.8.8` / `1.1.1.1` |
> | Blocking | disabled — isolates raw forwarding performance |

| Server | QPS | Avg Lat | P99 Lat | Lost |
|:-------|----:|--------:|--------:|-----:|
| ⚡ Unbound (C) | 1,102,095 | 1.00ms | 2.62ms | 0.16% |
| ⚡ PowerDNS (C++) | 899,679 | 2.07ms | 14.64ms | 0.18% |
| 🦀 **Ferrous-DNS** | **477,744** | **1.25ms** | **36.01ms** | **0.40%** |
| 🔷 Blocky (Go) | 102,299 | 78.44ms | 197.75ms | 0.38% |
| 🛡️ AdGuard Home | 100,971 | 3.74ms | 14.85ms | 1.88% |
| 🕳️ Pi-hole | 3,814 | 35.82ms | 349.64ms | 34.13% |

**Ferrous-DNS vs competitors:** 4.7× faster than AdGuard Home | 4.7× faster than Blocky | 125× faster than Pi-hole

PowerDNS Recursor and Unbound lead as purpose-built pure recursive resolvers (C++ and C) — no REST API, no Web UI, no database, no blocking engine. Ferrous-DNS runs all of these in the same process.

Cache hit P99: **~10–20µs** | Cache miss P99: **~1–3ms** | Hit rate: **~95%**

Full benchmark report and methodology: [`bench/benchmark-results.md`](https://github.com/andersonviudes/Ferrous-DNS/blob/main/bench/benchmark-results.md)
