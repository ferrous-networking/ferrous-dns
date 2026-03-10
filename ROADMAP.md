## 🗺️ Roadmap

### ✅ v0.1.0 - Foundation

- [x] Project structure with Clean Architecture
- [x] Rust workspace with 5 crates + tests
- [x] Axum web server integration
- [x] Modern dashboard with HTMX + Alpine.js
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
- [x] Conditional forwarding

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
- [x] Dashbodar Setting system status, pools dns status, cache ouverview, system information, kernel, uptime, load etc..

### 🎯 v0.7.0 - Security (Current)

- [x] Login / Auth
- [x] HTTPS for Web UI
- [x] API Key / token
- [x] Rate limiting DNS (token bucket per-subnet, slip TC=1, dry-run, NXDOMAIN budget)
- [x] DoS protection (TCP/DoT per-IP connection limiting, RAII guards)
- [x] DNS Tunneling Detection (two-phase: hot-path O(1) guard + background statistical analysis)
- [x] NXDomain hijack detection (detect ISP/upstream NXDOMAIN redirection)
- [x] Response IP filtering (block known C2 IPs in DNS responses)
- [ ] DGA Detection (Domain Generation Algorithm — entropy + n-gram + lexical analysis)
- [x] Separate listening ports for DoH and Admin UI

### 🎯 v0.8.0 - Export & Observability

- [ ] Config export/import (backup and restore)
- [ ] Query log export (CSV / JSON)
- [ ] Prometheus metrics
- [ ] OpenAPI / Swagger docs

### 🌟 v1.0.0 - Production Ready

- [ ] TOTP / 2FA
- [ ] Security audit
- [ ] Comprehensive test coverage (>80%)
- [ ] Production deployment guide
- [ ] API v1 stable
- [x] Full documentation

### 🎯 v1.1.0 - Next Features

- [ ] Suspicious TLD blocking (high-risk TLDs with dedicated UI — .tk, .top, .xyz, .buzz, .gq)
- [ ] Threat Intelligence feeds (abuse.ch, OpenPhish, PhishTank — native CSV/JSON ingestion + fast refresh)
- [ ] Newly Registered Domain (NRD) blocking (< 30 days, dedicated UI + configurable quarantine window)
- [ ] Time-based Blocking (per blocklist and per domain)
- [ ] Blocklist Dry-Run / Simulation Mode
- [ ] Blocklist Impact Analysis
- [ ] Per-blocklist hit stats (24h / 7d / 30d)
- [ ] DDNS HTTP endpoint
- [ ] ACME DNS-01 challenge endpoint
- [ ] Split-horizon DNS (Views)
- [ ] Per-group upstream DNS
- [ ] Webhook / push notifications
- [ ] Audit log for configuration changes
- [ ] WebSocket dashboard for slow query monitoring
- [ ] Query anomaly detection
- [ ] DoH bypass detection (detect malware using direct DoH to public resolvers)
---
