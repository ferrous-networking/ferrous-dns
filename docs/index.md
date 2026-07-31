# Ferrous DNS

<div align="center">

**High-performance DNS server with network-wide ad-blocking, written in Rust**

</div>

---

## What is Ferrous DNS?

Ferrous DNS is a self-hosted DNS server and network-wide ad-blocker designed as a high-performance alternative to Pi-hole and AdGuard Home. It runs as a **single binary** combining DNS resolution, REST API, and Web UI — with no external runtime dependencies.

Resolving from cache with blocking off, Ferrous DNS reaches **847,711 queries/second** (median of 3 runs, 8-core cpuset, 410,000-name working set) — the same tier as the resolvers written in C and C++, while running a REST API, Web UI, SQLite query log and blocking engine in the same process. Against the feature-comparable ad-blocking servers the gap is an order of magnitude: **9.9× Blocky**, **7.2× AdGuard Home**, **43× Pi-hole**.

With a 1,000,000-rule blocklist enabled throughput holds at **834,485 q/s** — blocking costs 1.6%, and the lead over the feature-comparable servers widens to 7.5× AdGuard Home and 8.5× Blocky. The query log is what costs: it brings throughput down to **262,298 q/s** and drops rows silently once its channel saturates. All three scenarios are published, including that one. Full tables and methodology: [Benchmarks](performance/benchmarks.md#benchmark-results).

---

## Feature Highlights

=== "Performance"

    - **Two-level cache** — fast per-thread L1 cache + shared L2 cache for maximum hit rate
    - **Smart eviction** — frequency-based eviction keeps popular domains cached
    - **In-flight coalescing** — deduplicates concurrent queries to a single upstream request
    - **Optimistic prefetch** — refreshes popular entries before they expire
    - **848K cache-hit queries/second** with blocking off (median of 3, ~10–15% run-to-run variance) — same tier as the C/C++ resolvers, 7.2x AdGuard Home, 43x Pi-hole
    - With a 1M-rule blocklist enabled this holds at 834K q/s (blocking costs 1.6%); enabling the query log drops it to 262K — see [Benchmarks](performance/benchmarks.md#benchmark-results)
    - Cache hit P99 < 35µs (actual ~10-20µs)

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

    - **HTTPS for dashboard and API** — single port with automatic HTTP → HTTPS redirect
    - Session-based authentication with login/logout
    - Named API tokens with SHA-256 hashed storage
    - First-run setup wizard for password configuration
    - Self-signed certificate generation from the UI
    - Login rate limiting and session management
    - **DNS rate limiting** — token bucket per subnet with NXDOMAIN budget, TC=1 slip, and dry-run mode
    - **TCP/DoT connection limiting** — per-IP limits prevent connection exhaustion
    - DNSSEC validation
    - DNS rebinding protection
    - **Malware detection** — DNS tunneling detection, DGA detection (Domain Generation Algorithm), NXDomain hijack detection, response IP filtering (C2 blocking)
    - PROXY Protocol v2 support
    - Pi-hole API compatibility

---

## Getting Started

<div class="grid cards" markdown>

- :material-rocket-launch:{ .lg .middle } **[Installation](getting-started/installation.md)**

    ---

    Docker, Docker Compose, or build from source

- :material-lightning-bolt:{ .lg .middle } **[Quick Start](getting-started/quick-start.md)**

    ---

    Get up and running in minutes

- :material-cog:{ .lg .middle } **[Configuration](configuration/index.md)**

    ---

    All configuration options explained

- :material-layers:{ .lg .middle } **[Architecture](architecture/overview.md)**

    ---

    Clean Architecture internals

</div>
