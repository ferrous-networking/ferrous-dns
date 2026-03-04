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
- [x] Upstream DNS forwarding udp 
- [x] Upstream DNS-over-HTTPS (DoH)
- [x] Upstream DNS-over-TLS (DoT)
- [x] Load balancing across upstream
- [x] Query caching with TTL
- [x] Local Dns records domain.local
- [x] Cache L1/L2 
- [x] Cache LFUK eviction (sliding window)
- [x] Bloom filter
- [x] Core tests coverage

### 🚧 v0.2.0 - Blocklist & Whitelist
                   
- [x] Auto detect Client ip and mac address                         
- [x] Client groups
- [x] Wildcard domain blocking (`*.ads.com`)
- [x] Whitelist support
- [x] Blocklist functionality
- [x] blocklist url import
- [x] blocklist regex support
- [x] button allows and block in the queries.html list
- [x] Conditional forwarding

### 🔮 v0.3.0 - Advanced Features 


- [x] Advanced analytics and graphs, upstrens ms, top sites blocked sites
- [x] DoQ upstream
- [x] https3, h3 upstream
- [x] IPv6 upstreams
- [x] dns name upstreams (e.: dns.google.com)
- [x] CNAME cloaking detection
- [x] Safe Search
- [x] Blockable services (1-click)

### 🎯 v0.4.0 - Parental Controls (Current)

- [ ] Scheduling per group + Parental Controls UI

### 🎯 v0.5.0 - server advanced features(Current)

- [ ] DoH/DoT server (listener-side)
- [ ] PTR auto-generation (add server local dns.: 192.168.1.10 → server.local) create a PTR reverse 10.1.168.192.in-addr.arpa → server.local
- [ ] DNS Rebinding Protection

### 🎯 v0.6.0 - Performance & Scale

- [ ] dashboard web socket performance slow queries
- [ ] Prometheus metrics
- [ ] Api compatible pi-hole
- [ ] Performance benchmarks vs. competitors
- [ ] OpenAPI / Swagger docs

### 🎯 v0.6.0 Security

- [ ] Login / Auth
- [ ] HTTPS para Web UI
- [ ] API Key / token
- [ ] Rate limiting DNS
- [ ] DoS protection


### 🌟 v1.0.0 - Production Ready

- [ ] Security audit
- [ ] Comprehensive test coverage (>80%)
- [ ] Production deployment guide
- [ ] API v1 stable
- [ ] Full documentation

### 🎯 v1.1.1 - next features

- [ ] Time-based Blocking
- [ ] Blocklist Dry-Run / Simulation Mode
- [ ] Blocklist Impact Analysis
- [ ] DDNS endpoint HTTP 
- [ ] ACME DNS-01 endpoint
- [ ] Split-horizon (Views), 

See [ROADMAP.md](ROADMAP.md) for detailed milestones.

---
