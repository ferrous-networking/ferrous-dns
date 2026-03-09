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
  L1 cache lookup             ~1-3µs     ← per-thread, zero locks
        │ miss
        ▼
  L2 cache lookup             ~10-20µs   ← shared, per-shard lock
        │ miss
        ▼
  In-flight check             ~200ns     ← is someone already fetching this?
        │ nobody fetching
        ▼
  Upstream query              ~1-50ms    ← DoH / DoT / DoQ / UDP
        │
        ▼
  Write to L2 + L1
        │
        ▼
  Send UDP response
```

Nothing in this path allocates memory for cache hits. No global locks. No expensive system calls for timing.

---

## L1/L2 Hierarchical Cache

### L1 — Per-Thread, Lock-Free

Each worker thread has its own private L1 cache. Because it is private to the thread, there is zero synchronization overhead.

- No locks, no contention -- direct memory access
- Holds the hottest ~100-500 entries per thread
- L1 hit overhead: ~1-3µs P99

### L2 — Shared, Sharded Cache

L2 is a shared cache split into independent shards (default: 4x CPU core count). Each shard has its own lock, so queries for different domains never block each other.

```
16-core machine → 64 shards

Query "google.com" → hash → shard #17 → lock shard #17 only
Query "reddit.com" → hash → shard #31 → lock shard #31 only
                                         ↑ never blocks each other
```

Under real-world load with hundreds of distinct active domains, contention is effectively zero.

- Capacity: up to 200,000 entries (configurable)
- L2 hit overhead: ~10-20µs P99
- Optimized hash function for fast domain name lookups

### Why Two Levels?

L1 absorbs the hottest queries (top ~0.1% of domains queried thousands of times per minute) without touching shared memory at all. L2 handles the long tail. Together they keep the cache hit rate above 95% for typical networks.

---

## Fast Negative Lookups

A significant fraction of DNS queries hit domains that are simply not in the blocklist. Without a quick pre-check, each query would trigger a full blocklist lookup across potentially millions of entries.

Ferrous DNS uses a probabilistic filter that answers one question almost instantly: **"Is this domain definitely not in the blocklist?"**

```
Query: "example.com"
         │
         ▼
   Quick pre-check:
   "Could this be blocked?" → NO  → skip all blocklist checks instantly
                             → YES → run full blocklist lookup (possible match)
```

- A "no" answer is guaranteed correct -- no blocked domain is ever missed
- False positive rate is kept very low
- Concurrent-safe with no locking
- Negligible overhead per lookup, regardless of blocklist size

For the ~99% of queries hitting common non-blocked domains, the entire blocklist engine adds negligible overhead per query.

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

The first query to see a cache miss becomes the "leader" and starts the upstream request. All subsequent requests for the same domain wait on a notification channel and receive the response the moment it arrives -- at zero additional upstream cost.

If the upstream request fails or is cancelled, all waiting clients are notified immediately and the tracking entry is cleaned up automatically.

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

Go-based DNS servers (Blocky, AdGuard Home) suffer from garbage collector pause spikes under load. Rust eliminates GC entirely. On top of that, Ferrous DNS enforces a strict no-allocation policy on the cache hit path:

- **Shared domain strings** -- domain names are stored once and shared by reference. Copying a reference costs ~1ns with no memory allocation
- **Stack-allocated record sets** -- most DNS responses contain 1-4 records, which are stored on the stack without heap allocation
- **Zero-copy case comparison** -- DNS names are compared case-insensitively without creating temporary copies
- **Fast hashing** -- an optimized hash function for short strings (domain names) provides ~3x faster lookups than the standard approach

---

## Low-Overhead Timing

Measuring cache hit latency requires a fast timer. Standard system clock calls cost ~20ns on x86_64, which adds measurable overhead to ~1µs cache hit operations.

Ferrous DNS reads the CPU's hardware timestamp counter directly, costing only ~1-5ns -- roughly 4-20x cheaper than a standard clock call. On ARM platforms, it falls back to a fast kernel clock with ~10-15ns overhead.

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

## Optimized Memory Allocator

Ferrous DNS uses a high-performance memory allocator optimized for server workloads:

- 2-3x faster than the default system allocator for small, short-lived allocations
- Per-thread memory pools minimize cross-thread contention
- Reduces long-term memory fragmentation under sustained server load

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

## UDP Buffer Tuning

The OS UDP receive buffer determines how many packets the kernel queues before the application processes them. With default buffer sizes, large query bursts overflow the kernel queue and are dropped silently.

Ferrous DNS sets enlarged socket buffers (8 MB send and receive) at startup. This directly improves the "queries lost" metric under peak load.

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
| L1 per-thread cache | Lock-free hits, ~1-3µs P99 |
| L2 sharded cache | Near-zero contention, ~10-20µs P99 |
| Fast negative lookups | Non-blocked domains skip blocklist checks instantly |
| In-flight coalescing | N identical cache-miss queries to 1 upstream request |
| Optimistic prefetch | Hot entries never expire; near-100% hit rate |
| Frequency-based eviction | Preserves most-active entries under memory pressure |
| Zero-allocation hot path | No memory allocation on cache hit path |
| Hardware timestamp counter | Hot-path timing at ~1-5ns vs ~20ns syscall |
| Async query log pipeline | Query logging never blocks the resolver |
| Optimized memory allocator | 2-3x faster allocation than system default |
| Parallel upstream strategy | Lowest cache-miss latency, transparent failover |
| UDP buffer tuning | Absorbs large bursts without packet loss |

---

## Benchmark Results

> **Host:** Intel Core i9-9900KF @ 3.60GHz | 8 cores / 16 threads / 46 GB RAM | Arch Linux | Kernel 6.12.75-1-lts
> **Tool:** dnsperf 2.14.0 | 60s per server | 10 concurrent clients | 187 domains (A, AAAA, MX, TXT, NS)
>
> **Docker config (identical for all servers):**
>
> | Setting | Value |
> |:--------|:------|
> | CPUs | `cpuset: 0-15` — 16 threads |
> | Network | host mode |
> | Upstreams | plain UDP `8.8.8.8` / `1.1.1.1` (parallel) |
> | Cache | enabled |
> | Blocking / denylists | disabled — isolates raw forwarding performance |
> | Rate limiting | disabled |
> | Log level | info |
> | Query logging (disk I/O) | disabled |

| Server | QPS | Avg Lat | P99 Lat | Completed | Lost |
|:-------|----:|--------:|--------:|----------:|-----:|
| ⚡ Unbound (C) | 952,810 | 0.98ms | 2.19ms | 99.81% | 0.19% |
| ⚡ PowerDNS (C++) | 884,128 | 2.06ms | 15.68ms | 99.82% | 0.18% |
| 🦀 **ferrous-dns** | **482,506** | **1.19ms** | **13.32ms** | **99.60%** | **0.40%** |
| 🔷 Blocky (Go) | 101,747 | 82.83ms | 206.78ms | 99.69% | 0.31% |
| 🛡️ AdGuard Home | 97,627 | 3.82ms | 15.27ms | 98.06% | 1.94% |
| 🕳️ Pi-hole | 2,066 | 46.43ms | 562.34ms | 51.00% | 49.00% |

**ferrous-dns vs competitors:** 4.9× faster than AdGuard Home | 4.7× faster than Blocky | 233× faster than Pi-hole

Unbound and PowerDNS Recursor lead as purpose-built pure recursive resolvers (C and C++) — no REST API, no Web UI, no database, no blocking engine. ferrous-dns runs all of these in the same single-process binary.

Cache hit P99: **~10–20µs** | Cache miss P99: **~1–3ms** | Hit rate: **~95%**

Full benchmark report and methodology: [`bench/benchmark-results.md`](https://github.com/andersonviudes/ferrous-dns/blob/main/bench/benchmark-results.md)
