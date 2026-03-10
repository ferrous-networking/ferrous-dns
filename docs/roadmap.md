# Roadmap

---

## Completed

### v0.1.0 — Foundation

- [x] Clean Architecture workspace with 5 crates
- [x] Axum web server + REST API
- [x] Modern dashboard (HTMX + Alpine.js)
- [x] SQLite persistence
- [x] Full DNS resolver (A, AAAA, CNAME, MX, TXT, PTR, NS, SRV)
- [x] Upstream DNS forwarding (UDP)
- [x] DNS-over-HTTPS (DoH) upstream
- [x] DNS-over-TLS (DoT) upstream
- [x] Load balancing across upstreams
- [x] Query caching with TTL
- [x] Local DNS records
- [x] L1/L2 hierarchical cache
- [x] LFUK eviction (sliding window)
- [x] Bloom filter for negative lookups

### v0.2.0 — Blocklist & Allowlist

- [x] Auto client detection (IP + MAC)
- [x] Client groups
- [x] Wildcard domain blocking (`*.ads.com`)
- [x] Allowlist support
- [x] Blocklist URL import
- [x] Regex blocklist support
- [x] Allow/Block buttons in query log
- [x] Conditional forwarding

### v0.3.0 — Advanced Features

- [x] Analytics and graphs (upstream latency, top sites, blocked sites)
- [x] DNS-over-QUIC (DoQ) upstream
- [x] HTTP/3 upstream
- [x] IPv6 upstreams
- [x] DNS name upstreams (resolved at startup)
- [x] CNAME cloaking detection
- [x] Safe Search enforcement (Google, Bing, YouTube)
- [x] Blockable services (1-click categories)

### v0.4.0 — Parental Controls

- [x] Per-group blocklist assignment
- [x] Time-based scheduling per group
- [x] Parental Controls UI

### v0.5.0 — Server Advanced Features

- [x] DoH/DoT server (serve encrypted DNS to clients)
- [x] PROXY Protocol v2 (real client IP behind load balancers)
- [x] Auto PTR generation from local A records
- [x] DNS rebinding protection

### v0.6.0 — Performance & Scale

- [x] Pi-hole compatible API
- [x] Performance benchmarks vs. competitors (438K QPS)
- [x] Dashboard settings: system status, DNS pool status, cache overview, system info
- [x] In-flight coalescing (cache stampede prevention)
- [x] TSC timer (~1-5ns) for hot path timing
- [x] Separate listening ports for DoH and Admin UI

---

## In Progress

### v0.7.0 — Security & Malware Detection

- [x] Login / authentication
- [x] HTTPS for Web UI
- [x] API Key / token system
- [ ] TOTP / 2FA
- [x] Rate limiting DNS (token bucket per-subnet, slip TC=1, dry-run, NXDOMAIN budget)
- [x] DoS protection (TCP/DoT per-IP connection limiting, RAII guards)
- [x] DNS Tunneling Detection (two-phase: hot-path O(1) guard + background statistical analysis)
- [ ] DGA Detection (Domain Generation Algorithm — entropy + n-gram + lexical analysis)
- [ ] Threat Intelligence feeds (abuse.ch, OpenPhish, PhishTank — IoC ingestion)
- [ ] Suspicious TLD blocking (high-risk TLDs: .tk, .top, .xyz, .buzz, .gq)
- [ ] Newly Registered Domain (NRD) blocking (< 30 days, feed-based)
- [x] Response IP filtering (block known C2 IPs in DNS responses)
- [x] NXDomain hijack detection (detect ISP/upstream NXDOMAIN redirection)
- [ ] Read-only / lockdown mode (disable config changes via flag)
- [x] Separate DoH and Admin UI ports

---

## Planned

### v0.8.0 — Observability

- [ ] Config export/import (backup and restore)
- [ ] Query log export (CSV / JSON)
- [ ] Prometheus metrics endpoint
- [ ] OpenAPI / Swagger documentation

### v1.0.0 — Production Ready

- [ ] Security audit
- [ ] Comprehensive test coverage (> 80%)
- [ ] Production deployment guide
- [ ] API v1 stable (no breaking changes)
- [x] Full documentation

### v1.1.0 — Advanced Features

- [ ] Time-based blocking (per blocklist and per domain)
- [ ] Blocklist dry-run / simulation mode
- [ ] Blocklist impact analysis
- [ ] Per-blocklist hit stats (24h / 7d / 30d)
- [ ] DDNS HTTP endpoint
- [ ] ACME DNS-01 challenge endpoint
- [ ] Split-horizon DNS (views)
- [ ] Per-group upstream DNS
- [ ] Webhook / push notifications
- [ ] Audit log for configuration changes
- [ ] WebSocket dashboard for real-time monitoring
- [ ] Query anomaly detection
- [ ] DoH bypass detection (detect malware using direct DoH to public resolvers)

---

## RFC Compliance

| RFC | Topic | Status |
|:----|:------|:------:|
| RFC 1035 | DNS basics — A, AAAA, CNAME, MX, TXT, PTR | Done |
| RFC 6891 | EDNS0 OPT records | Done |
| RFC 7766 | DNS over TCP | Done |
| RFC 7858 | DNS-over-TLS (DoT) — server + upstream | Done |
| RFC 8484 | DNS-over-HTTPS (DoH) — server + upstream | Done |
| RFC 9250 | DNS-over-QUIC (DoQ) upstream | Done |
| RFC 9114 | HTTP/3 upstream | Done |
| RFC 4035 | DNSSEC validation | Done |
| [PROXY Protocol v2](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) | PROXY Protocol v2 (HAProxy spec) | Done |
| RFC 7828 | edns-tcp-keepalive | Planned |

---

## Version Summary

| Version | Focus | Status |
|:--------|:------|:------:|
| v0.1.0 | Foundation — DNS + Cache + API | Done |
| v0.2.0 | Blocklist & Allowlist | Done |
| v0.3.0 | Advanced Features — DoQ, HTTP/3, Safe Search | Done |
| v0.4.0 | Parental Controls + Scheduling | Done |
| v0.5.0 | DoH/DoT server, PROXY Protocol v2, PTR auto-gen, Rebinding | Done |
| v0.6.x | Performance & Scale | Done |
| v0.7.0 | Security & Malware Detection — Auth, Rate Limiting, Tunneling Detection | In Progress |
| v0.8.0 | Observability — Prometheus, OpenAPI, Config export | Planned |
| v1.0.0 | Production Ready — Security audit, > 80% coverage | Planned |
| v1.1.0 | Advanced — Split-horizon, Webhooks, DoH bypass detection | Planned |
