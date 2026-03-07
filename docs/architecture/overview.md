# Architecture Overview

Ferrous DNS is built on **Clean Architecture** principles with strict layer separation. All business logic lives in the innermost layers, completely isolated from frameworks, databases, and I/O.

---

## Layer Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                            CLI                                   │
│        (entrypoint, dependency wiring, server bootstrap)        │
├───────────────┬──────────────────────────┬──────────────────────┤
│     API       │        API (Pi-hole)     │         Jobs         │
│  (Axum REST)  │     (Pi-hole v6 compat)  │  (background tasks)  │
├───────────────┴──────────────────────────┴──────────────────────┤
│                        Application                               │
│              (use cases, ports/traits, services)                │
├─────────────────────────────────────────────────────────────────┤
│                          Domain                                  │
│          (entities, value objects, domain errors)               │
│                      zero external deps                         │
└─────────────────────────────────────────────────────────────────┘
                              ↑
                       Infrastructure
               (SQLite, cache L1/L2, DNS adapters,
                resolvers, transport, repositories)
```

### Dependency Rules

```
domain          ← no dependencies
application     ← domain only
infrastructure  ← domain + application (implements ports)
api             ← application (use cases via DI, never infra directly)
api-pihole      ← application (same use cases as api, never imports api)
jobs            ← application (ports only, never imports infrastructure)
cli             ← all crates (the only place concrete types are wired)
```

**Critical rule**: `api` and `api-pihole` never import each other. Only `cli` knows both.

---

## DNS Resolution Pipeline

The resolver is a layered decorator chain. Each layer wraps the previous one and implements the same `DnsResolver` trait:

```
FilteredResolver          ← safe search enforcement, query filters
  └── CachedResolver      ← L1/L2 cache + in-flight coalescing + prefetch
        └── DnssecResolver ← DNSSEC signature validation
              └── LocalPtrResolver ← auto PTR for local A records
                    └── CoreResolver ← upstream forwarding (UDP/DoH/DoT/DoQ/H3)
```

Each layer is independent. Adding new functionality means adding a new layer without touching existing code.

### In-Flight Coalescing

When multiple clients query the same domain simultaneously during a cache miss, Ferrous DNS sends exactly **one** upstream request and fans out the response to all waiters:

```
Client A ─┐
Client B ─┼──► 1 upstream request ──► response ──► all clients
Client C ─┘
```

This eliminates thundering-herd on popular domains under high load.

---

## Upstream Load Balancing

```
Query
  │
  ▼
Pool Router
  │
  ├── Pool 1 (priority 1, healthy)
  │     ├── Strategy: Parallel
  │     └── Upstreams: DoQ + DoH + DoH
  │
  └── Pool 2 (priority 2, fallback)
        ├── Strategy: Failover
        └── Upstreams: UDP + UDP
```

The pool router selects the highest-priority pool with at least one healthy upstream. Upstream health is monitored continuously.

---

## Write Pipeline for Query Logs

The query log write path is fully async and never blocks the DNS hot path:

```
DNS handler
    │
    │ try_send (non-blocking)
    ▼
Channel (10k capacity)
    │
    │ batch read (up to 2k entries)
    ▼
Background flush task
    │
    │ single INSERT transaction
    ▼
SQLite (WAL mode)
```

If the channel is full (backpressure), entries are dropped and a warning is logged. The DNS response is never delayed.

---

## Technology Stack

| Layer | Technology |
|:------|:----------|
| Runtime | Tokio async + rayon |
| Web server | Axum 0.8 |
| DNS protocol | Hickory DNS 0.26-alpha |
| Cache L2 | DashMap + FxBuildHasher (sharded) |
| Cache L1 | Thread-local LRU (lock-free) |
| Bloom filter | bloomfilter (AtomicBloom) |
| Cache eviction | LFU-K sliding window |
| Timer hot path | rdtsc x86_64 (~1–5ns) / CLOCK_MONOTONIC_COARSE |
| Database | SQLite via sqlx async |
| Strings | `Arc<str>`, CompactString |
| Collections (hot path) | SmallVec (stack-allocated) |
| Sockets | socket2 (UDP buffer tuning) |
| Allocator | mimalloc |
| CPU affinity | core_affinity |
| Transport | rustls, tokio-rustls, quinn (QUIC), reqwest (HTTP/3) |
| Frontend | HTMX + Alpine.js + TailwindCSS |

---

## Design Patterns

### Decorator (Resolver Pipeline)

Each resolver layer wraps the previous one via `Arc<dyn DnsResolver>`. Adding caching, DNSSEC, or rate limiting requires only a new struct — existing layers are never modified.

### Builder (Complex Object Construction)

Objects with multiple optional parameters use Builder pattern:

```rust
let resolver = ResolverBuilder::new(pool_manager)
    .with_cache(dns_cache, config.cache_ttl)
    .with_dnssec()
    .with_filters(filters)
    .with_prefetch(predictor)
    .build()?;
```

### Strategy (Algorithms)

Upstream resolution strategy (`Parallel` / `Balanced` / `Failover`) and cache eviction policy (`hit_rate` / `lfu` / `lru`) are interchangeable at runtime via configuration. No conditional branches in hot-path code.

### Observer (Async Events)

DNS query side effects (logging, metrics) are decoupled from query processing via async channels. The hot path emits events with a non-blocking `try_send`. Background workers consume and persist them.

### Repository (Data Access Abstraction)

Use cases interact with data through traits (`BlocklistSourceRepository`, `QueryLogRepository`). SQLite implementations live in the infrastructure layer and are invisible to business logic.

### Guard (RAII Cleanup)

Resources like in-flight map entries use Rust's `Drop` trait for guaranteed cleanup, even on cancellation or panic:

```rust
// Automatically removes the in-flight entry on Drop
struct InflightLeaderGuard { ... }
impl Drop for InflightLeaderGuard { ... }
```

---

## Hot Path Performance Rules

The DNS hot path is: **UDP recv → bloom check → L1 cache → L2 cache → in-flight → upstream → send**

Key constraints on the hot path:

- No heap allocations (`Vec::new()`, `Box::new()`, `String::new()`)
- No blocking locks — DashMap per-shard or thread-local only
- No precise syscalls — use `rdtsc` (~1–5ns) not `Instant::now()`
- No string cloning — use `Arc<str>` (clone = atomic increment only)
- Case-insensitive comparison without allocation: `eq_ignore_ascii_case()`

---

## Single Binary

Ferrous DNS ships as a single binary containing:

- DNS server (UDP + TCP)
- DoT server (TCP/TLS)
- DoH server (HTTP/HTTPS)
- REST API (Axum)
- Web dashboard (static files embedded)
- Background jobs (blocklist sync, cache maintenance, WAL checkpoint)

No external dependencies at runtime — just the binary and an SQLite file.
