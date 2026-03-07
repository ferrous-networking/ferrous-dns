# DNS & Upstream Configuration

The `[dns]` section controls upstream resolution, DNSSEC, local records, and upstream pool management.

---

## Basic DNS Options

```toml
[dns]
upstream_servers = []
query_timeout = 3
default_strategy = "Parallel"
dnssec_enabled = true
block_private_ptr = true
block_non_fqdn = true
local_domain = "lan"
local_dns_server = "10.0.0.1:53"
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `upstream_servers` | `[]` | Fallback upstreams when no pool matches (same URL format as pools) |
| `query_timeout` | `3` | Seconds to wait for an upstream response |
| `default_strategy` | `"Parallel"` | Default strategy for `upstream_servers`: `"Parallel"` or `"Sequential"` |
| `dnssec_enabled` | `true` | Validate DNSSEC signatures on upstream responses |
| `block_private_ptr` | `true` | Block PTR lookups for private/RFC-1918 IP ranges |
| `block_non_fqdn` | `true` | Block queries for non-fully-qualified domain names |
| `local_domain` | `"lan"` | Local domain suffix appended to short hostnames |
| `local_dns_server` | — | Router/DHCP server used for PTR lookups and client hostname resolution |

---

## Upstream URL Formats

Ferrous DNS supports all major DNS transport protocols:

| Protocol | URL Format | Example |
|:---------|:-----------|:--------|
| Plain UDP | `udp://host:port` | `udp://8.8.8.8:53` |
| Plain TCP | `tcp://host:port` | `tcp://8.8.8.8:53` |
| DNS-over-HTTPS | `https://host/path` | `https://cloudflare-dns.com/dns-query` |
| DNS-over-TLS | `tls://host:port` | `tls://1.1.1.1:853` |
| DNS-over-QUIC | `doq://host:port` | `doq://dns.adguard-dns.com:853` |
| HTTP/3 | `h3://host/path` | `h3://dns.google/dns-query` |

You can also use DNS names directly (resolved at startup):

```toml
servers = [
    "doq://dns.adguard-dns.com:853",   # hostname resolved at startup
    "https://dns.google/dns-query",
]
```

---

## Upstream Pools {#upstream-pools}

Pools group upstream servers with a resolution strategy. Multiple pools can be defined with different priorities.

```toml
[[dns.pools]]
name = "primary"
strategy = "Parallel"
priority = 1
servers = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[[dns.pools]]
name = "fallback"
strategy = "Failover"
priority = 2
servers = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
]
```

| Option | Description |
|:-------|:------------|
| `name` | Unique pool identifier |
| `strategy` | Resolution strategy (see below) |
| `priority` | Lower number = higher priority. The highest-priority healthy pool is used |
| `servers` | List of upstream servers (URL format) |

### Strategies

| Strategy | Behavior |
|:---------|:---------|
| `"Parallel"` | Queries all upstreams simultaneously, returns the fastest response. Best latency. |
| `"Balanced"` | Round-robin across healthy upstreams. Best load distribution. |
| `"Failover"` | Uses the first upstream; fails over to the next only on error. |

!!! tip "Recommended setup"
    Use `"Parallel"` with DoQ/DoH upstreams for lowest cache-miss latency. Add a `"Failover"` pool with plain UDP as a lower-priority fallback.

---

## Health Checks {#health-checks}

Ferrous DNS continuously monitors upstream health and routes around failed servers:

```toml
[dns.health_check]
interval = 30           # Seconds between health check probes
timeout = 2000          # Milliseconds to wait for a health response
failure_threshold = 3   # Consecutive failures before marking unhealthy
success_threshold = 2   # Consecutive successes to restore a server
```

A server is temporarily excluded from rotation when `failure_threshold` consecutive checks fail, and restored after `success_threshold` consecutive successes.

---

## Local DNS Records {#local-records}

Define static A/AAAA records served directly by Ferrous DNS, bypassing upstream resolution:

```toml
[[dns.local_records]]
hostname = "router"
domain = "local"
ip = "192.168.1.1"
record_type = "A"
ttl = 300

[[dns.local_records]]
hostname = "nas"
domain = "local"
ip = "192.168.1.50"
record_type = "A"
ttl = 300

# IPv6
[[dns.local_records]]
hostname = "server"
domain = "local"
ip = "fd00::1"
record_type = "AAAA"
ttl = 300
```

| Field | Description |
|:------|:------------|
| `hostname` | Short hostname (without domain) |
| `domain` | Domain suffix — full name is `hostname.domain` |
| `ip` | IPv4 or IPv6 address |
| `record_type` | `"A"` for IPv4, `"AAAA"` for IPv6 |
| `ttl` | Time-to-live in seconds |

### Auto PTR Generation

When you define a local A record, Ferrous DNS automatically creates a PTR record. For example, `server.local → 192.168.1.100` also creates `100.1.168.192.in-addr.arpa → server.local`.

This means reverse DNS lookups work without any extra configuration.

---

## Conditional Forwarding

Route specific domains to internal resolvers (e.g. your AD domain controller, split-horizon DNS):

Conditional forwarding is managed via the dashboard UI (Clients > Groups > Forwarding) or the REST API. It allows you to route queries for specific domains to a designated upstream, while all other queries follow the normal pool routing.

Example use case: route `corp.internal` to `10.0.0.5:53` (Active Directory) while everything else uses DoH upstreams.

---

## DNSSEC

When `dnssec_enabled = true`, Ferrous DNS validates DNSSEC signatures on all upstream responses. Queries that fail DNSSEC validation return `SERVFAIL`.

!!! note
    DNSSEC validation adds a small latency overhead on cache misses. For maximum throughput benchmarking, you can disable it: `dnssec_enabled = false`.

---

## Supported Record Types

Ferrous DNS supports all common DNS record types per RFC 1035:

| Type | Description |
|:-----|:------------|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `CNAME` | Canonical name |
| `MX` | Mail exchanger |
| `TXT` | Text record |
| `PTR` | Reverse DNS |
| `NS` | Name server |
| `SRV` | Service locator |

---

## Local DNS Server {#local-dns-server}

```toml
[dns]
local_dns_server = "192.168.1.1:53"
```

`local_dns_server` points to your router or DHCP server. Ferrous DNS uses it for three distinct purposes.

---

### 1. PTR Lookups — Reverse DNS for Clients

When a client queries Ferrous DNS, the server knows the client's IP address. To display a human-readable hostname in the dashboard, logs, and per-client group matching, Ferrous DNS issues a PTR (reverse DNS) lookup for that IP.

```
Client IP: 192.168.1.42
         │
         ▼
Ferrous DNS sends: PTR 42.1.168.192.in-addr.arpa → local_dns_server
         │
         ▼
Router responds:   "desktop-work.lan"
         │
         ▼
Dashboard shows:   desktop-work.lan (192.168.1.42)
```

Without `local_dns_server`, clients appear in the dashboard only as raw IP addresses. With it, they appear with their full hostname.

!!! note "block_private_ptr"
    The `block_private_ptr` option controls whether PTR queries from **external clients** for RFC-1918 addresses are blocked. It does not affect the internal PTR lookups Ferrous DNS makes to `local_dns_server` for its own client tracking.

---

### 2. DHCP Hostname Resolution

Many DHCP servers register client hostnames alongside their leases. `local_dns_server` allows Ferrous DNS to resolve these names, so devices show up with the same names your router assigns them — without requiring any manual configuration on the Ferrous DNS side.

This is especially useful for:

- Parental control rules tied to device names instead of IPs
- Client group assignment based on hostname patterns
- Dashboard readability when many devices are on the network

---

### 3. Upstream Server Name Resolution {#upstream-name-resolution}

Upstream server URLs may contain hostnames rather than bare IP addresses:

```toml
servers = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "tls://dns.quad9.net:853",
]
```

At startup, Ferrous DNS must resolve these hostnames to IP addresses before it can establish connections. If `local_dns_server` is configured, these startup lookups are sent there first — which matters in environments where:

- The machine running Ferrous DNS has no system resolver configured (common in containers)
- You want to avoid a circular dependency (Ferrous DNS cannot query itself to bootstrap its own upstreams)
- Your internal network routes DNS differently than the default system resolver

```
Startup: resolve "dns.adguard-dns.com"
              │
              ▼ (if local_dns_server is set)
    192.168.1.1:53  →  returns 94.140.14.14
              │
              ▼
    Connection established to doq://94.140.14.14:853
```

If `local_dns_server` is not set, hostname resolution at startup falls back to the system resolver (`/etc/resolv.conf`).

---

### Recommended Setup

For a typical home or office network:

```toml
[dns]
local_domain     = "lan"          # short hostnames resolve as name.lan
local_dns_server = "192.168.1.1:53"  # your router's IP
```

| Scenario | Effect |
|:---------|:-------|
| Client `192.168.1.42` connects | Dashboard shows `laptop.lan` instead of raw IP |
| Upstream URL `doq://dns.adguard-dns.com:853` | Hostname resolved via router at startup |
| New device joins the network | Hostname pulled from router's DHCP table |

