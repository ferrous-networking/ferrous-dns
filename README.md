<div align="center">

<img src="web/static/logo.svg" alt="Ferrous DNS" width="80" height="80"/>

# Ferrous DNS

**A blazingly fast, memory-safe DNS server with network-wide ad-blocking**

[![CI](https://github.com/ferrous-networking/Ferrous-DNS/actions/workflows/ci.yml/badge.svg)](https://github.com/ferrous-networking/Ferrous-DNS/actions/workflows/ci.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/andersonviudes/ferrous-dns?logo=docker)](https://hub.docker.com/r/andersonviudes/ferrous-dns)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Stars](https://img.shields.io/github/stars/ferrous-networking/Ferrous-DNS?style=social)](https://github.com/ferrous-networking/Ferrous-DNS/stargazers)

*Modern alternative Dns server*

[docker](#-docker) • [docker-compose](#-docker-compose) • [Roadmap](ROADMAP.md) • [Benchmarks](benchmark-results.md)

</div>

---

## ⚡ Performance

Benchmarked against the most popular DNS servers using the same plain UDP upstream (`8.8.8.8` / `1.1.1.1`) for a fair comparison — 20s run, 10 concurrent clients, 125-domain dataset:

| Server          |        QPS | Avg Latency | vs Ferrous-DNS |
|:----------------|-----------:|:-----------:|:--------------:|
| 🦀 Ferrous-DNS  | **377,777** | **0.58ms**  | —              |
| ⚡ Unbound       |    203,967  |    0.85ms   | 1.85× slower   |
| 🛡️ AdGuard Home |    105,837  |    2.45ms   | 3.57× slower   |
| 🕳️ Pi-hole      |      7,652  |   21.99ms   | 49× slower     |

→ [Full benchmark report with raw dnsperf output](benchmark-results.md)

---

## 📖 About

Ferrous DNS is a modern, high-performance DNS server with built-in ad-blocking capabilities. Written in Rust, it offers superior performance and memory safety compared to traditional solutions.

**Key capabilities:**

> ✅ = Available now &nbsp;|&nbsp; 🔜 = Coming soon (on roadmap)

**Performance & Architecture**
- ⚡ **Rust-powered** ✅ — Zero GC pauses, ~10–20µs P99 cache hits; (C/dnsmasq) and  (Go) can't match this without a garbage collector
- 🧠 **L1/L2 Hierarchical Cache** ✅ — Thread-local L1 (lock-free) + sharded L2 DashMap with LFUK sliding-window eviction and Bloom filter for ultra-fast negative lookups
- 🦀 **Memory Safe by Design** ✅ — Rust ownership model eliminates entire classes of vulnerabilities (buffer overflows, use-after-free, data races) without a runtime
- 📦 **Single Binary** ✅ — DNS server + REST API + Web UI in one process; no PHP, no lighttpd, no Python — just one container

**Encrypted & Modern DNS**
- 🔒 **DoH + DoT upstream** ✅ — Forward queries to upstream resolvers over HTTPS or TLS
- 🚀 **DNS-over-QUIC (DoQ) + HTTP/3 upstream** ✅ — Cutting-edge transports that Pi-hole and most competitors don't support yet
- 🌐 **IPv6 upstreams + DNS-name resolvers** ✅ — e.g. `dns.google.com` resolved at startup
- 🛡️ **DoH + DoT server (listener-side)** ✅ — Serve encrypted DNS directly to clients on your network (v0.5.0)
- 🔄 **DNS Rebinding Protection** ✅ — Prevent malicious sites from attacking your internal network (v0.5.0)

**Blocking & Filtering**
- 🚫 **Network-wide Ad & Tracker Blocking** ✅ — Blocklists, regex patterns, wildcard domains (`*.ads.com`), whitelist, and 1-click blockable services
- 🕵️ **CNAME Cloaking Detection** ✅ — Catches trackers that hide behind first-party CNAMEs — a privacy gap Pi-hole leaves open
- 🔍 **Safe Search Enforcement** ✅ — Force SafeSearch on Google, Bing, YouTube, and more per client group
- 👨‍👩‍👧 **Per-Group Parental Controls + Scheduling** ✅ — Assign different blocklists and access schedules to each client group; AdGuard Home and Pi-hole require workarounds for this

**Client Intelligence**
- 📡 **Auto Client Detection** ✅ — Automatically identifies client IP and MAC address without manual configuration
- 👥 **Client Groups** ✅ — Segment devices into groups with different policies (kids, work, IoT)
- 🔀 **Conditional Forwarding** ✅ — Route specific domains to internal resolvers (e.g. your router)
- 📊 **Advanced Analytics** ✅ — Upstream latency graphs, top queried domains, top blocked domains, per-group stats

**Observability & Integrations (Roadmap)**
- 📈 **Prometheus Metrics** 🔜 — Native metrics endpoint for Grafana and alerting (v0.8.0)
- 📄 **OpenAPI / Swagger Docs** 🔜 — Self-documenting REST API (v0.8.0)
- 🔁 **Pi-hole Compatible API** ✅ — Drop-in replacement for existing Pi-hole integrations and dashboards (v0.6.0)
- 🌍 **Split-Horizon DNS** 🔜 — Serve different answers per client/group/network (v1.1.0)
- 🔔 **Webhook / Push Notifications** 🔜 — Alerts for anomalous query patterns (v1.1.0)

**Security (Roadmap)**
- 🔐 **Auth + TOTP/2FA** 🔜 — Login, API keys, and two-factor authentication (v0.7.0)
- 🛑 **Rate Limiting + DoS Protection** 🔜 — DNS query rate limiting per client (v0.7.0)

**Deployment**
- 🐳 **Docker Ready** ✅ — Multi-arch images (amd64, arm64) for Docker and Docker Compose
- 📋 **Full DNS Records** ✅ — RFC 1035 compliant with A, AAAA, CNAME, MX, TXT, PTR and local DNS records

---

## 🚀 Installation

### 🐳 Docker

Quick start with Docker:

```bash
docker run -d \
  --name ferrous-dns \
  --restart always \
  --network host \
  --user root \
  -e FERROUS_CONFIG=/data/config/ferrous-dns.toml \
  -e FERROUS_DATABASE=/data/db/ferrous.db \
  -e FERROUS_DNS_PORT=53 \
  -e FERROUS_WEB_PORT=8080 \
  -e FERROUS_BIND_ADDRESS=0.0.0.0 \
  -e FERROUS_LOG_LEVEL=info \
  -e TZ=America/Sao_Paulo \
  --dns 10.0.0.1 \
  --cap-add NET_ADMIN \
  --cap-add SYS_TIME \
  --cap-add SYS_NICE \
  --cap-add NET_BIND_SERVICE \
  andersonviudes/ferrous-dns:latest
```

Access the dashboard at `http://localhost:8080`

### 🐳 Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  ferrous-dns:
    image: andersonviudes/ferrous-dns:latest
    container_name: ferrous-dns
    restart: always
    network_mode: host
    user: root
    environment:
      # Config file (opcional - só usa se existir)
      - FERROUS_CONFIG=/data/config/ferrous-dns.toml
      # Database
      - FERROUS_DATABASE=/data/db/ferrous.db
      # Network
      - FERROUS_DNS_PORT=53
      - FERROUS_WEB_PORT=8080
      - FERROUS_BIND_ADDRESS=0.0.0.0
      # Logging
      - FERROUS_LOG_LEVEL=info
      # Timezone
      - TZ=America/Sao_Paulo
    dns:
      - 10.0.0.1
    cap_add:
      - NET_ADMIN
      - SYS_TIME
      - SYS_NICE
      - NET_BIND_SERVICE
    volumes:
      - ferrous-data:/data/

volumes:
  ferrous-data:
```

Start the service:

```bash
docker-compose up -d
```

### ⚙️ Configuration

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERROUS_CONFIG` | - | Path to config file |
| `FERROUS_DNS_PORT` | `53` | DNS server port |
| `FERROUS_WEB_PORT` | `8080` | Web dashboard port |
| `FERROUS_BIND_ADDRESS` | `0.0.0.0` | Bind address |
| `FERROUS_DATABASE` | `/var/lib/ferrous-dns/ferrous.db` | Database path |
| `FERROUS_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |


---

## 🗺️ Roadmap

Check out our [detailed roadmap](ROADMAP.md) to see what's planned for future releases.

---

## Dashboard

![img.png](img.png)


## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

- **Report bugs**: [GitHub Issues](https://github.com/ferrous-networking/Ferrous-DNS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ferrous-networking/Ferrous-DNS/discussions)

---

## 📄 License

This project is dual-licensed under:
- [MIT License](https://opensource.org/licenses/MIT)
- [Apache License 2.0](https://opensource.org/licenses/Apache-2.0)

You may choose either license for your use.

---

<div align="center">

**Made with ❤️ and 🦀 by [Anderson Viudes](https://github.com/andersonviudes)**

If you find this project useful, please consider giving it a ⭐

[⬆ Back to Top](#-ferrous-dns)

</div>
