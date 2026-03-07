# Ferrous DNS

<div align="center">

**High-performance DNS server with network-wide ad-blocking, written in Rust**

</div>

---

## What is Ferrous DNS?

Ferrous DNS is a self-hosted DNS server and network-wide ad-blocker designed as a high-performance alternative to Pi-hole and AdGuard Home. It runs as a **single binary** combining DNS resolution, REST API, and Web UI — with no external runtime dependencies.

At **147,241 queries/second** under identical Docker conditions (16 CPUs, cache enabled, rate limiting disabled), Ferrous DNS is **1.58× faster than AdGuard Home**, **1.61× faster than Blocky**, and **33× faster than Pi-hole** — running a full feature stack in a single process. PowerDNS Recursor (220K QPS) and Unbound (217K QPS) lead as purpose-built pure recursive resolvers with no additional features.

---

## Feature Highlights

=== "Performance"

    - **L1/L2 hierarchical cache** — thread-local lock-free L1 + sharded DashMap L2
    - **LFUK eviction** with sliding window and Bloom filter for negative lookups
    - **In-flight coalescing** — deduplicates concurrent queries to a single upstream request
    - **TSC timer** (~1–5ns overhead) for sub-microsecond cache hit measurements
    - **mimalloc** allocator for reduced allocation overhead
    - Cache hit P99 < 35µs (actual ~10–20µs)

=== "Encrypted DNS"

    - **Upstream**: plain UDP, DoH, DoT, DoQ, and HTTP/3
    - **Server-side**: serve DoH and DoT directly to clients (RFC 7858 / RFC 8484)
    - IPv6 upstreams and DNS-name resolvers (e.g. `dns.google.com`)

=== "Blocking & Filtering"

    - Blocklists with regex patterns and wildcard domains (`*.ads.com`)
    - Allowlist support
    - 1-click blockable service categories
    - CNAME cloaking detection
    - Safe Search enforcement (Google, Bing, YouTube)

=== "Client Management"

    - Auto client detection by IP and MAC address
    - Client groups with independent policies (kids, work, IoT)
    - Per-group parental controls with time-based scheduling
    - Conditional forwarding — route specific domains to internal resolvers

=== "Security"

    - DNSSEC validation
    - DNS rebinding protection
    - PROXY Protocol v2 support
    - Pi-hole API compatibility

---

## Quick Comparison

| Server          |        QPS | vs Ferrous DNS |
|:----------------|-----------:|:--------------:|
| PowerDNS (C++)  |   220,635  | 1.50× faster   |
| Unbound (C)     |   217,527  | 1.48× faster   |
| **Ferrous DNS** | **147,241** | —              |
| AdGuard Home    |    93,159  | 1.58× slower   |
| Blocky (Go)     |    91,417  | 1.61× slower   |
| Pi-hole         |     4,427  | 33× slower     |

[Full benchmark report](performance/benchmarks.md)

---

## Getting Started

<div class="grid cards" markdown>

- **[Installation](getting-started/installation.md)** — Docker, Docker Compose, or build from source
- **[Quick Start](getting-started/quick-start.md)** — Get up and running in minutes
- **[Configuration](configuration/index.md)** — All configuration options explained
- **[Architecture](architecture/overview.md)** — Clean Architecture internals

</div>
