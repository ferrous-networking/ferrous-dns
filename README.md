<div align="center">

<img src="logo.png" alt="Ferrous DNS" width="80" height="80"/>

# Ferrous DNS

**High-performance DNS server with network-wide ad-blocking, written in Rust**

[![CI](https://github.com/ferrous-networking/ferrous-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/ferrous-networking/ferrous-dns/actions/workflows/ci.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/ferrousnetworking/ferrous-dns?logo=docker)](https://hub.docker.com/r/ferrousnetworking/ferrous-dns)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[Documentation](https://ferrous-networking.github.io/ferrous-dns/) • [Quick Start](https://ferrous-networking.github.io/ferrous-dns/getting-started/quick-start/) • [Configuration](https://ferrous-networking.github.io/ferrous-dns/configuration/) • [Benchmarks](https://ferrous-networking.github.io/ferrous-dns/performance/benchmarks/) • [Roadmap](ROADMAP.md)

</div>

---

## Documentation

Full documentation is available at **[ferrous-networking.github.io/ferrous-dns](https://ferrous-networking.github.io/ferrous-dns/)**.

## Performance

At **482,506 queries/second** under identical Docker conditions (16 CPUs, cache enabled, log info, rate limiting disabled), ferrous-dns is **4.9x faster than AdGuard Home**, **4.7x faster than Blocky**, and **233x faster than Pi-hole** — all running a full feature stack (DNS server, REST API, Web UI, SQLite query log, blocking engine) in a single process. PowerDNS Recursor (884K QPS) and Unbound (952K QPS) lead as purpose-built pure recursive resolvers with no additional features.

[Full benchmark report](https://ferrous-networking.github.io/ferrous-dns/performance/benchmarks/)

---

## Features

**Performance** — [Cache docs](https://ferrous-networking.github.io/ferrous-dns/configuration/cache/)
- [L1/L2 hierarchical cache](https://ferrous-networking.github.io/ferrous-dns/configuration/cache/) — thread-local lock-free L1 + sharded DashMap L2 with LFUK eviction and Bloom filter for negative lookups
- In-flight coalescing — deduplicates concurrent queries for the same domain to a single upstream request
- Single binary — DNS server, REST API, Web UI, and SQLite query log in one process; no extra dependencies

**Dashboard** — [Dashboard docs](https://ferrous-networking.github.io/ferrous-dns/features/dashboard/)
- Real-time query log with block/allow actions
- Query rate, blocked queries, top domains, top clients
- Upstream latency graphs and health status
- Dark mode, built with HTMX + Alpine.js + TailwindCSS

**Encrypted DNS** — [Encrypted DNS docs](https://ferrous-networking.github.io/ferrous-dns/features/encrypted-dns/)
- Upstream: plain UDP, [DoH](https://ferrous-networking.github.io/ferrous-dns/features/encrypted-dns/), [DoT](https://ferrous-networking.github.io/ferrous-dns/features/encrypted-dns/), [DoQ](https://ferrous-networking.github.io/ferrous-dns/features/encrypted-dns/), and [HTTP/3](https://ferrous-networking.github.io/ferrous-dns/features/encrypted-dns/)
- Server (listener): [DoH and DoT](https://ferrous-networking.github.io/ferrous-dns/features/encrypted-dns/) — serve encrypted DNS directly to clients
- IPv6 upstreams and DNS-name resolvers (e.g. `dns.google.com` resolved at startup)

**Upstream Management** — [Upstream docs](https://ferrous-networking.github.io/ferrous-dns/features/upstream-management/)
- [Named pools](https://ferrous-networking.github.io/ferrous-dns/features/upstream-management/) with priority-based routing and automatic failover
- Resolution strategies: [Parallel, Balanced, Failover](https://ferrous-networking.github.io/ferrous-dns/features/upstream-management/)
- [Health checks](https://ferrous-networking.github.io/ferrous-dns/features/upstream-management/) with configurable thresholds and global fallback upstreams

**Blocking & Filtering** — [Blocking docs](https://ferrous-networking.github.io/ferrous-dns/features/blocking-filtering/)
- [Blocklists](https://ferrous-networking.github.io/ferrous-dns/features/blocking-filtering/) with regex patterns and wildcard domains (`*.ads.com`)
- [Allowlist](https://ferrous-networking.github.io/ferrous-dns/features/blocking-filtering/)
- [1-click blockable service categories](https://ferrous-networking.github.io/ferrous-dns/features/blocking-filtering/) — Advertising, Analytics, Social Media, Telemetry, Adult Content, Gambling
- [CNAME cloaking detection](https://ferrous-networking.github.io/ferrous-dns/features/blocking-filtering/) — catches trackers hiding behind first-party CNAMEs
- [Safe Search](https://ferrous-networking.github.io/ferrous-dns/features/blocking-filtering/) enforcement for Google, Bing, YouTube, and DuckDuckGo

**Client Management** — [Client docs](https://ferrous-networking.github.io/ferrous-dns/features/client-management/)
- [Auto client detection](https://ferrous-networking.github.io/ferrous-dns/features/client-management/) by IP, MAC address, and hostname
- [Client groups](https://ferrous-networking.github.io/ferrous-dns/features/client-management/) with independent policies (e.g. Kids, Work, IoT, Guest)
- [Parental controls](https://ferrous-networking.github.io/ferrous-dns/features/client-management/) with time-based scheduling per group
- [Conditional forwarding](https://ferrous-networking.github.io/ferrous-dns/features/client-management/) — route specific domains to internal resolvers

**Security** — [Security docs](https://ferrous-networking.github.io/ferrous-dns/features/security/)
- [HTTPS](https://ferrous-networking.github.io/ferrous-dns/features/security/) for dashboard and REST API (single port, automatic HTTP -> HTTPS redirect)
- [Session-based authentication](https://ferrous-networking.github.io/ferrous-dns/features/security/) (login/logout with rate limiting)
- [Named API tokens](https://ferrous-networking.github.io/ferrous-dns/features/security/) (SHA-256 hashed, `X-Api-Key` header)
- [First-run setup wizard](https://ferrous-networking.github.io/ferrous-dns/features/security/) for password configuration
- [Self-signed certificate generation](https://ferrous-networking.github.io/ferrous-dns/features/security/) from the UI
- [DNS rate limiting](https://ferrous-networking.github.io/ferrous-dns/configuration/rate-limiting/) — token bucket per subnet with NXDOMAIN budget, TC=1 slip, and dry-run mode
- [TCP/DoT connection limiting](https://ferrous-networking.github.io/ferrous-dns/configuration/rate-limiting/) — per-IP RAII guards prevent connection exhaustion
- [DNSSEC validation](https://ferrous-networking.github.io/ferrous-dns/features/security/) (RFC 4035)
- [PROXY Protocol v2](https://ferrous-networking.github.io/ferrous-dns/features/security/) support

**Malware Detection** — [Malware Detection docs](https://ferrous-networking.github.io/ferrous-dns/features/malware-detection/)
- [DNS tunneling detection](https://ferrous-networking.github.io/ferrous-dns/features/malware-detection/) — two-phase detection (hot path O(1) + background statistical analysis) catches C2 beaconing, data exfiltration, and DGA malware via entropy, query rate, unique subdomains, TXT proportion, and NXDOMAIN ratio
- [DNS rebinding protection](https://ferrous-networking.github.io/ferrous-dns/features/malware-detection/) — blocks public domains resolving to private IPs (RFC-1918), preventing browser-based attacks on routers, NAS, and IoT devices
- [NXDomain hijack detection](https://ferrous-networking.github.io/ferrous-dns/features/malware-detection/) — automatically detects and neutralizes ISP NXDOMAIN interception by probing upstreams with `.invalid` domains (RFC 6761) and converting hijacked responses back to proper NXDOMAIN
- [Response IP filtering](https://ferrous-networking.github.io/ferrous-dns/features/malware-detection/) — downloads C2 IP threat feeds (abuse.ch, Feodo Tracker) and blocks DNS responses that resolve to known command-and-control server IPs, stopping malware before it connects

**Compatibility & Deployment**
- [Pi-hole v6 API compatibility](https://ferrous-networking.github.io/ferrous-dns/features/pihole-compat/) — drop-in replacement for existing integrations and third-party apps
- [Docker multi-arch images](https://ferrous-networking.github.io/ferrous-dns/getting-started/installation/) (amd64, arm64)
- RFC 1035 compliant: A, AAAA, CNAME, MX, TXT, PTR, NS, SRV, and [local DNS records](https://ferrous-networking.github.io/ferrous-dns/configuration/dns/)
- Auto PTR generation for local A records

---

## Installation

### Docker

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
  ferrousnetworking/ferrous-dns:latest
```

Access the dashboard at `http://localhost:8080`

See [full installation guide](https://ferrous-networking.github.io/ferrous-dns/getting-started/installation/) for Docker Compose, build from source, and Raspberry Pi setup.

### Docker Compose

```yaml
services:
  ferrous-dns:
    image: ferrousnetworking/ferrous-dns:latest
    container_name: ferrous-dns
    restart: always
    network_mode: host
    user: root
    environment:
      - FERROUS_CONFIG=/data/config/ferrous-dns.toml
      - FERROUS_DATABASE=/data/db/ferrous.db
      - FERROUS_DNS_PORT=53
      - FERROUS_WEB_PORT=8080
      - FERROUS_BIND_ADDRESS=0.0.0.0
      - FERROUS_LOG_LEVEL=info
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

```bash
docker compose up -d
```

### Build from Source

```bash
git clone https://github.com/ferrous-networking/ferrous-dns.git
cd ferrous-dns
cargo build --release
./target/release/ferrous-dns --config ferrous-dns.toml
```

### Configuration

See the [full configuration reference](https://ferrous-networking.github.io/ferrous-dns/configuration/) for all options.

#### Environment Variables

| Variable              | Default                               | Description                         |
|:----------------------|:--------------------------------------|:------------------------------------|
| `FERROUS_CONFIG`      | —                                     | Path to TOML config file (optional) |
| `FERROUS_DNS_PORT`    | `53`                                  | DNS server port                     |
| `FERROUS_WEB_PORT`    | `8080`                                | Web dashboard port                  |
| `FERROUS_BIND_ADDRESS`| `0.0.0.0`                             | Bind address                        |
| `FERROUS_DATABASE`    | `/var/lib/ferrous-dns/ferrous.db`     | SQLite database path                |
| `FERROUS_LOG_LEVEL`   | `info`                                | Log level: debug, info, warn, error |

---

## Dashboard

![Dashboard](img.png)

[Dashboard docs](https://ferrous-networking.github.io/ferrous-dns/features/dashboard/)

---

## Contributing

Bug reports, feature requests, and pull requests are welcome.

- Issues: [GitHub Issues](https://github.com/ferrous-networking/ferrous-dns/issues)
- Discussions: [GitHub Discussions](https://github.com/ferrous-networking/ferrous-dns/discussions)
- Docs: [Contributing Guide](https://ferrous-networking.github.io/ferrous-dns/contributing/)

---

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
