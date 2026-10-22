## 🗺️ Roadmap

### ✅ v0.1.0 - Foundation

- [x] Project structure with Clean Architecture
- [x] Rust workspace with 5 crates + tests
- [x] Axum web server integration
- [x] Modern dashboard with Alpine.js
- [x] REST API endpoints structure
- [x] SQLite persistence
- [x] Basic DNS server implementation
- [x] Full DNS resolver (A, AAAA, CNAME, MX, TXT, PTR, RFC...)
- [x] Upstream DNS forwarding UDP
- [x] Upstream DNS-over-HTTPS (DoH)
- [x] Upstream DNS-over-TLS (DoT)
- [x] Load balancing across upstreams
- [x] Query caching with TTL
- [x] Local DNS records (domain.local)
- [x] Cache L1/L2
- [x] Cache LFUK eviction (sliding window)
- [x] Bloom filter
- [x] Core tests coverage

### ✅ v0.2.0 - Blocklist & Whitelist

- [x] Auto detect client IP and MAC address
- [x] Client groups
- [x] Wildcard domain blocking (`*.ads.com`)
- [x] Whitelist support
- [x] Blocklist functionality
- [x] Blocklist URL import
- [x] Blocklist regex support
- [x] Allow and block buttons in query log
- [x] Local domain forwarding to the router (`local_domain` + `local_dns_server`)

### ✅ v0.3.0 - Advanced Features

- [x] Advanced analytics and graphs (upstream latency, top sites, blocked sites)
- [x] DNS-over-QUIC (DoQ) upstream
- [x] HTTP/3 upstream
- [x] IPv6 upstreams
- [x] DNS name upstreams (e.g. dns.google.com)
- [x] CNAME cloaking detection
- [x] Safe Search enforcement
- [x] Blockable services (1-click)

### ✅ v0.4.0 - Parental Controls 

- [x] Per-group blocklist assignment (assign specific blocklists to client groups)
- [x] Scheduling per group + Parental Controls UI

### ✅ v0.5.0 - Server Advanced Features 

- [x] DoH/DoT server (listener-side, serve encrypted DNS to clients)
- [x] PROXY Protocol v2 (real client IP behind load balancers)
- [x] PTR auto-generation from A records (192.168.1.10 → server.local creates 10.1.168.192.in-addr.arpa PTR)
- [x] DNS Rebinding Protection

### ✅ v0.6.0 - Performance & Scale 

- [x] Pi-hole compatible API
- [x] Performance benchmarks vs. competitors
- [x] Settings dashboard: system status, upstream pool health, cache overview, system information (kernel, uptime, load)

### ✅ v0.7.0 - Security

- [x] Login / Auth
- [x] HTTPS for Web UI
- [x] API Key / token
- [x] Rate limiting DNS (token bucket per-subnet, slip TC=1, dry-run, NXDOMAIN budget)
- [x] DoS protection (TCP/DoT per-IP connection limiting, RAII guards)
- [x] DNS Tunneling Detection (two-phase: hot-path O(1) guard + background statistical analysis)
- [x] NXDomain hijack detection (detect ISP/upstream NXDOMAIN redirection)
- [x] Response IP filtering (block known C2 IPs in DNS responses)
- [x] DGA Detection (Domain Generation Algorithm — entropy + n-gram + lexical analysis)
- [x] Separate listening ports for DoH and Admin UI

### ✅ v0.8.0 - Export & Observability

- [x] Config export/import (backup and restore)
- [x] Prometheus metrics
- [x] OpenAPI / Swagger docs
- [x] Predictive prefetch — delivered via `cache_optimistic_refresh` (popularity/recency-weighted renewal ahead of expiry + serve-stale, RFC 8767; since v0.9 each entry renews on its own timer); speculative Markov co-occurrence prefetch evaluated and dropped as low-value/privacy-risk for a forwarder
- [x] Extended DNS Errors (RFC 8914) — blocked, rate-limited, DNSSEC and upstream failures carry an EDE code and text
- [x] Server-side DNS Cookies (RFC 7873) — HMAC server cookies for clients, permissive by default
- [x] Configurable block response — `block_mode` answers blocked names with `null_ip` (`0.0.0.0` / `::`), `nxdomain`, `nodata` or `refused`
- [x] Hot-reload of upstream pools — pool changes apply without a restart
- [x] Query log client/hostname filter

### 🎯 v0.9.0 - Protocol Hardening & Privacy (Current)

#### Protocol & privacy

- [x] Upstream anti-spoofing — off-path forgery validation on every plain-UDP (Do53) upstream response, for every record type: transaction-ID + question name/type checks always on; DNS Cookies (RFC 7873) always sent and validated gracefully; opt-in 0x20 QNAME case randomization (draft-vixie-dns-0x20) via `qname_case_randomization`, stripped from the response before it is cached so it never reaches clients. Encrypted transports (DoT/DoH/DoQ) skip cookie/0x20 *validation* (TLS already authenticates the upstream), tolerating upstreams that normalize QNAME case. Upstream source ports rotate so a discovered port goes stale
- [x] DNSSEC downgrade protection — `Insecure` requires the parent's authenticated NSEC/NSEC3 proof of an unsigned delegation (RFC 4035 §5.2); the walk tells zone cuts from plain names, so stripping RRSIGs or the DS denial from a signed zone yields Bogus. Unproven DS denials are counted at `GET /api/dnssec/stats` (`ds_denials_unproven`) to expose upstreams that strip DNSSEC records
- [x] EDNS UDP payload size negotiation + correct TC truncation (RFC 6891 §6.2.5 / RFC 7766) — honor client-advertised buffer, set TC=1 on oversized responses
- [x] DNSSEC validation enforcement (RFC 4035 / RFC 6840) — `dnssec_mode = "Strict"` answers SERVFAIL on Bogus and Indeterminate (`Permissive`, the default, validates and tags without refusing), AD bit set/clear from validation, honor client CD bit
- [x] DNS-over-QUIC (DoQ) server listener (RFC 9250) — serve encrypted DNS to clients over QUIC (upstream DoQ already supported)
- [x] DNS64 / NAT64 AAAA synthesis (RFC 6147) — `[dns64]` `enabled` / `prefix` (well-known `64:ff9b::/96`, /96 only) synthesizes AAAA from A records for IPv6-only clients; reverse PTR synthesis; `dns64_synthesized` query-log tag + Prometheus metric. NAT64 packet translation remains the network gateway's job
- [ ] EDNS Client Subnet (RFC 7871) — strip client ECS by default for privacy; optional configurable subnet injection upstream for CDN-correct results
- [x] Custom sinkhole IP for blocked responses (configurable A/AAAA target beyond `0.0.0.0` / `::`) — `[blocking]` `sinkhole_ipv4` / `sinkhole_ipv6`, applied to `null_ip` blocked answers
- [x] TOTP / 2FA — two-phase login (TOTP enrollment + `/auth/2fa/verify`) plus WebAuthn passkeys as a second factor or passwordless login, gated on `[auth.webauthn]`; API keys are exempt
- [x] Conditional forwarding — route a list of domain suffixes (a corporate zone, a national ccTLD) to a chosen upstream pool, for every client or per client group; unsigned internal zones can opt out of DNSSEC validation and rebinding protection while public zones keep both, and per-group answers are cached apart so split-horizon results never reach another group — `[[dns.pools]]` `domains` / `groups` / `internal`
- [x] DNS Cookies strict mode — every reply echoes the client's cookie; with `require_valid_cookie` a UDP query without a valid server cookie gets BADCOOKIE and a fresh cookie to retry with (RFC 7873 §5.2.3), while TCP/DoT/DoH/DoQ are exempt
- [x] Negative caching per RFC 2308 — NXDOMAIN/NODATA cached for the SOA negative TTL (held to 300–3600 s); an upstream SERVFAIL is never cached and fails over to the next server
- [x] Overload protection — bounded workloads shed upstream-bound queries once the upstream budget is full, while cached and local answers keep flowing; shed and drop totals exported on `/metrics`
- [x] Fuzzing — cargo-fuzz harnesses for the query fast path, upstream relay, 0x20 handling, DNSSEC records, PROXY v2 headers and blocklist text, with a regression corpus run in CI

#### Filtering & local DNS

- [x] DNS Filter what-if backtest — replay recent traffic against a pasted list or regex before applying it, and see which domains it would newly block or free; plus a single-domain test
- [x] Manual allow/deny rules take top priority over blocklists, schedules, blocked services and the detection engines
- [x] Wildcard local DNS records (`*.lab.example`)
- [x] Malware detection settings page — every detection engine configurable from the UI, behind one master switch

#### Query log, dashboard & cache

- [x] Query log ANSWER column (resolved IPs), client protocol per query (UDP/TCP/DoT/DoH/DoQ) and a client dropdown filter
- [x] Cache Control page — every cached entry with its TTL, hits and refresh count
- [x] Per-entry cache refresh — each popular entry renews on its own timer ahead of expiry instead of a periodic scan; expiry and eviction are event-driven too
- [x] Dashboard Upstream and Cache Refreshes cards; dashboard aggregates served from per-minute rollups
- [x] Restart-required banner when a saved setting only applies after a restart
- [x] Web UI works offline — every third-party asset is vendored and served from the binary
- [x] Settings explain how to write each upstream URL (UDP, TCP, DoT, DoH, DoQ, HTTP/3)
- [x] Sidebar shows the running version, linked to its release notes and the repository

#### Pi-hole compatibility

- [x] Pi-hole v6 API conformance — responses mirror FTL, plus every remaining v6 route Ferrous can answer, for dashboard integrations such as Homarr

### 🌟 v1.0.0 - Production Ready

- [x] Supply-chain scanning & vulnerability disclosure (cargo audit + Trivy image scan + Dependabot + secret scanning + SECURITY.md private reporting)
- [ ] Security audit (threat model + manual review / pentest of the DNS parsing, auth and API attack surface) — the threat model is published in Security Hardening; the external review is pending
- [ ] Comprehensive test coverage (>80%)
- [ ] Production deployment guide
- [ ] API v1 stable
- [x] Full documentation

### 🎯 v1.1.0 - Next Features

- [ ] Suspicious TLD blocking (high-risk TLDs with dedicated UI — .tk, .top, .xyz, .buzz, .gq)
- [ ] Threat Intelligence feeds (abuse.ch, OpenPhish, PhishTank — native CSV/JSON ingestion + fast refresh) — IP lists already feed response IP filtering; domain feeds are not supported yet
- [ ] Newly Registered Domain (NRD) blocking (< 30 days, dedicated UI + configurable quarantine window)
- [ ] Time-based Blocking (per blocklist and per domain) — per-group schedules shipped in v0.4.0
- [ ] Blocklist Dry-Run / Simulation Mode — live: log what a list would block without blocking it
- [x] Blocklist Impact Analysis — delivered as the DNS Filter what-if backtest (v0.9.0)
- [ ] Per-blocklist hit stats (24h / 7d / 30d)
- [ ] DDNS HTTP endpoint
- [ ] ACME DNS-01 challenge endpoint
- [ ] Split-horizon DNS (Views) — conditional forwarding already keeps each group's answers for routed zones apart
- [ ] Per-group upstream DNS — conditional forwarding routes chosen domains per group; a per-group default upstream is not possible yet
- [ ] Webhook / push notifications
- [ ] Audit log for configuration changes
- [ ] WebSocket dashboard for slow query monitoring
- [ ] Query anomaly detection
- [ ] DoH bypass detection (detect malware using direct DoH to public resolvers)
- [ ] mDNS / Bonjour device discovery — passive UDP 5353 listener (multicast 224.0.0.251) to label clients by device name instead of bare IPs (the listener landed behind `dns.mdns_enabled`; it does not parse names or label clients yet)
---
