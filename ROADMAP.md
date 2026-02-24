## 🗺️ Roadmap

### ✅ v0.1.0 - Foundation 

- [x] Project structure with Clean Architecture
- [x] Rust workspace with 5 crates + tests
- [x] Axum web server integration
- [x] Modern dashboard with HTMX + Alpine.js
- [x] REST API endpoints structure
- [x] SQLite persistence
- [x] Basic DNS server implementation
- [x] Full DNS resolver (A, AAAA, CNAME, MX, TXT, PTR, etc.. RFC)
- [x] Upstream DNS forwarding udp 
- [x] Upstream DNS-over-HTTPS (DoH)
- [x] Upstream DNS-over-TLS (DoT)
- [x] Load balancing across upstreams
- [x] Query caching with TTL
- [x] Local Dns records domain.local
- [x] Cache L1/L2 hierárquico
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

### 🔮 v0.3.0 - Advanced Features (Current)

- [ ] dash board web socket performace slow queries 
- [ ] Advanced analytics and graphs
- [ ] Query filtering rules
- [x] DoQ upstream
- [x] https3, h3 upstream
- [ ] IPv6 upstreams
- [ ] dns name upstreams (e.: dns.google.com) 
- [ ] Client identification
- [ ] Comprehensive documentation
- [x] CNAME cloaking detection
- [ ] Safe Search
- [ ] Serviços bloqueáveis (1-click)

### 🎯 v0.4.0 - Security


- [ ] Autenticação web (login)
- [ ] HTTPS para Web UI
- [ ] API Key / token
- [ ] Rate limiting DNS
- [ ] DoS protection

### 🎯 v0.5.0 - Performance & Scale

- [ ] Prometheus metrics
- [ ] Api compatible pi-hole
- [ ] Performance benchmarks vs competitors
- [ ] OpenAPI / Swagger docs

### 🌟 v1.0.0 - Production Ready

- [ ] Security audit
- [ ] Comprehensive test coverage (>80%)
- [ ] Production deployment guide
- [ ] API v1 stable
- [ ] Full documentation

See [ROADMAP.md](ROADMAP.md) for detailed milestones.

---
