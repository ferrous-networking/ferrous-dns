# Ferrous DNS

<div align="center">

**High-performance DNS server with network-wide ad-blocking, written in Rust**

[![CI](https://github.com/ferrous-networking/Ferrous-DNS/actions/workflows/ci.yml/badge.svg)](https://github.com/ferrous-networking/Ferrous-DNS/actions/workflows/ci.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/andersonviudes/ferrous-dns?logo=docker)](https://hub.docker.com/r/andersonviudes/ferrous-dns)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

</div>

---

## What is Ferrous DNS?

Ferrous DNS is a self-hosted DNS server and network-wide ad-blocker designed as a high-performance alternative to Pi-hole and AdGuard Home. It runs as a **single binary** combining DNS resolution, REST API, and Web UI — with no external runtime dependencies.

At **438,925 queries/second**, Ferrous DNS is nearly **2x faster than Unbound**, **3.3x faster than Blocky**, **4x faster than AdGuard Home**, and **64x faster than Pi-hole** — benchmarked under identical conditions.

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
| **Ferrous DNS** | **438,925** | —              |
| Unbound         |   224,194  | 1.96x slower   |
| Blocky          |   133,446  | 3.29x slower   |
| AdGuard Home    |   109,068  | 4.03x slower   |
| Pi-hole         |     6,902  | 64x slower     |

[Full benchmark report](performance/benchmarks.md)

---

## Getting Started

<div class="grid cards" markdown>

- **[Installation](getting-started/installation.md)** — Docker, Docker Compose, or build from source
- **[Quick Start](getting-started/quick-start.md)** — Get up and running in minutes
- **[Configuration](configuration/index.md)** — All configuration options explained
- **[Architecture](architecture/overview.md)** — Clean Architecture internals

</div>
