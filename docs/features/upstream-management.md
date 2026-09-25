# Upstream Management

Ferrous DNS gives you full control over how DNS queries are forwarded to the internet — which servers to use, how to balance load between them, what to do when one fails, and how to monitor their health.

---

## Upstream URL Formats

All upstream servers are specified as URLs. Every major DNS transport protocol is supported, and every one of them takes a hostname or an IP address — you never need to use bare IP addresses:

| Protocol | Format | Example | Port |
|:---------|:-------|:--------|:-----|
| Plain UDP | `udp://host:port` | `udp://8.8.8.8:53` | required, usually 53 |
| Plain TCP | `tcp://host:port` | `tcp://8.8.8.8:53` | required, usually 53 |
| DNS-over-HTTPS (DoH) | `https://host[:port]/path` | `https://cloudflare-dns.com/dns-query` | optional, defaults to 443 |
| DNS-over-TLS (DoT) | `tls://host:port` | `tls://dns.google:853` | required, usually 853 |
| DNS-over-QUIC (DoQ) | `doq://host:port` | `doq://dns.adguard-dns.com:853` | required, usually 853 |
| HTTP/3 | `h3://host[:port]/path` | `h3://dns.google/dns-query` | optional, defaults to 443 |

A bare `IP:PORT` with no scheme, such as `8.8.8.8:53`, is plain UDP. An IPv6 address goes in brackets, as in any URL: `doq://[2a10:50c0::ad1:ff]:853`, `https://[2606:4700:4700::1111]/dns-query`.

An address Ferrous DNS cannot read is rejected at startup, by the configuration API, and by the Settings page before it saves, with a message that says how to fix it — for example `missing port — DNS-over-QUIC usually uses 853, e.g. doq://dns.adguard-dns.com:853`.

### Hostname or IP address? {#hostname-or-ip}

Both work. For the encrypted protocols (DoT, DoQ, DoH, HTTP/3), prefer the hostname:

- It is the name the server's TLS certificate is checked against, and it is sent as SNI during the handshake. With an IP address, the certificate must list that IP.
- Some providers identify your account or device by the hostname you connect to, such as AdGuard DNS private servers (`doq://<device-id>.d.adguard-dns.com:853`). An IP address loses that.

### Coming from AdGuard {#from-adguard}

AdGuard Home and the AdGuard DNS dashboard write DNS-over-QUIC as `quic://host`, usually without a port. Ferrous DNS uses `doq://` and needs the port:

| AdGuard shows | Write in Ferrous DNS |
|:--------------|:---------------------|
| `quic://dns.adguard-dns.com` | `doq://dns.adguard-dns.com:853` |
| `quic://<device-id>.d.adguard-dns.com` | `doq://<device-id>.d.adguard-dns.com:853` |
| `tls://dns.adguard-dns.com` | `tls://dns.adguard-dns.com:853` |
| `https://dns.adguard-dns.com/dns-query` | unchanged |

### How hostnames are resolved {#hostname-resolution}

```toml
servers = [
    "doq://dns.adguard-dns.com:853",   # looked up at startup, when pools are saved, and retried if that failed
    "https://dns.google/dns-query",
]
```

Ferrous DNS looks upstream hostnames up when it starts and whenever the pools are saved, and uses up to four addresses per family:

1. **`local_dns_server`**, when set: your router is asked for the A and AAAA records, with the same anti-spoofing checks as every query sent to it.
2. **The system resolver** (the host's `/etc/resolv.conf` / OS resolver), when `local_dns_server` is unset, does not answer within two seconds, or has no address for the name.

The router comes first so that upstream hostnames keep resolving on a machine that uses Ferrous DNS as its own resolver. There, the system lookup can never succeed: nothing answers it while Ferrous DNS starts, and afterwards Ferrous DNS has no resolved upstream to ask. One consequence: when the router answers, an `/etc/hosts` entry for an upstream hostname is not consulted.

!!! note "If the lookup fails"
    The server is kept without an address, and the log shows `Failed to resolve upstream hostname, keeping unresolved and retrying in the background`. Ferrous DNS looks it up again at the health-check interval, doubling the wait up to five minutes while it keeps failing, with no restart needed. Until then, `udp://`, `tcp://`, `tls://` and `doq://` servers fail every query with `has no IP address yet`, which Settings > System Status shows for that server; `https://` and `h3://` also try the system resolver when a query needs them. See [Troubleshooting](../troubleshooting.md#hostname-upstream-never-comes-up).

---

## Upstream Pools

Pools are named groups of upstream servers with a shared resolution strategy and priority. You can define as many pools as you need.

```toml
[[dns.pools]]
name    = "primary"
strategy = "Parallel"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[[dns.pools]]
name    = "fallback"
strategy = "Failover"
priority = 2
servers  = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
]
```

| Field | Description |
|:------|:------------|
| `name` | Unique identifier for the pool |
| `strategy` | How queries are distributed across servers in this pool |
| `priority` | Lower number = higher priority. The highest-priority pool with at least one healthy server is always used |
| `servers` | List of upstream server URLs |
| `weight` | Optional relative weight for the pool (`int`, default unset). Accepted, persisted, and exposed via the API, but **not yet consumed** by the load balancer — the `Balanced` strategy is plain round-robin. Reserved for future weighted distribution |

### Pool Routing

When a query arrives, Ferrous DNS selects the pool with:

1. The **lowest priority number** (highest priority)
2. At least **one healthy upstream** in rotation

If all servers in pool 1 are down, queries automatically fall through to pool 2 — no configuration changes required.

```text
Query arrives
     │
     ▼
Pool 1 (priority=1) — any healthy server? → YES → use pool 1
                                          → NO  ↓
Pool 2 (priority=2) — any healthy server? → YES → use pool 2
                                          → NO  ↓
upstream_servers fallback (if configured)
```

---

## Resolution Strategies

Each pool has an independent strategy that controls how its servers are used.

---

### Parallel — Lowest Cache-Miss Latency

Queries **all servers simultaneously** and returns the first successful response. Slower responses are discarded.

```toml
[[dns.pools]]
name     = "parallel-pool"
strategy = "Parallel"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]
```

**How it works:**

```text
Query "example.com"
        │
        ├──► Server A  ──► responds in  8ms  ← returned to client
        ├──► Server B  ──► responds in 12ms  ← discarded
        └──► Server C  ──► responds in 15ms  ← discarded

Client gets the answer in 8ms (fastest server wins)
```

**Best for:** Production environments where cache-miss latency matters. The cost is extra upstream traffic — each query hits all servers simultaneously.

!!! tip
    Use 2–4 servers per Parallel pool. More than 4 adds diminishing returns while increasing upstream load.

---

### Balanced — Even Load Distribution

Distributes queries in **round-robin** across all healthy servers. If a server fails a health check, it is temporarily removed from the rotation and restored automatically when it recovers.

```toml
[[dns.pools]]
name     = "balanced-pool"
strategy = "Balanced"
priority = 1
servers  = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "tls://1.1.1.1:853",
]
```

**How it works:**

```text
Query 1 → Server A
Query 2 → Server B
Query 3 → Server C
Query 4 → Server A  (Server D is down — skipped)
Query 5 → Server B
...
```

**Best for:** High-volume deployments where you want to spread load across multiple providers without hammering all of them on every query.

---

### Failover — Primary/Backup

Uses the **first server** in the list as the primary. Falls over to the next server only if the primary fails. Returns to the primary as soon as it recovers.

```toml
[[dns.pools]]
name     = "failover-pool"
strategy = "Failover"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",    # primary — always used when healthy
    "https://cloudflare-dns.com/dns-query",  # first fallback
    "udp://8.8.8.8:53",                 # last resort
]
```

**How it works:**

```text
Normal state:    all queries → Server A (primary)

Server A fails:  all queries → Server B (first fallback)

Server A recovers: all queries → Server A (back to primary)
```

**Best for:** Scenarios where you have a preferred upstream (e.g. your ISP's DNS, a NextDNS profile, or an internal resolver) and want a backup only when it's unavailable.

---

## Combining Strategies

You can use different strategies in different pools. A common setup:

```toml
# Pool 1: Parallel encrypted upstreams for speed
[[dns.pools]]
name     = "encrypted"
strategy = "Parallel"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

# Pool 2: Failover to plain UDP if encrypted upstreams are unreachable
[[dns.pools]]
name     = "plain-fallback"
strategy = "Failover"
priority = 2
servers  = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
]
```

With this setup, all queries go through encrypted DoQ/DoH when available. If all three encrypted servers are simultaneously unreachable (network issue, firewall block), queries automatically fall back to plain UDP — so DNS never fully breaks.

---

## Health Checks

Ferrous DNS continuously monitors every upstream server. Unhealthy servers are removed from rotation and restored automatically when they recover.

```toml
[dns.health_check]
interval          = 30    # seconds between probes per server
timeout           = 2000  # milliseconds to wait for a probe response
failure_threshold = 3     # consecutive failures before marking unhealthy
success_threshold = 2     # consecutive successes to restore a server
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `interval` | `30` | Seconds between health probes per server |
| `timeout` | `2000` | Milliseconds to wait for a probe response |
| `failure_threshold` | `3` | Consecutive failures before marking a server unhealthy |
| `success_threshold` | `2` | Consecutive successes required to restore a server to rotation |

**Health check flow:**

```text
Server A: probe every 30s

3 consecutive failures → marked UNHEALTHY → removed from rotation
                                              ↓
                                         Health probes continue
                                              ↓
2 consecutive successes → marked HEALTHY → restored to rotation
```

The health checker runs independently of query traffic, so a flaky server is detected and removed without clients ever seeing a failed response — the pool routes around it transparently.

If every server in every pool is marked unhealthy at once, Ferrous DNS fails open and queries them anyway, in pool priority order, until a probe marks one healthy again. The checker can lag reality — a network change after boot, or probes that fail while real queries would succeed — and refusing every query would turn a stale verdict into a total outage. Entering and leaving this state is logged once each (`No upstream server is marked healthy; querying all servers anyway`).

An answer that came back truncated over UDP and was retried over TCP is attributed to the configured server with a `(tcp retry)` suffix, e.g. `udp://9.9.9.9:53 (tcp retry)`, in the query log and upstream statistics.

The current state of every pool and server is shown on the dashboard under
**Settings > System Status**:

![Settings — the System Status tab with server and performance metrics, upstream pool health, and the cache overview](../assets/dashboard/dashboard-settings.png)

---

## Global Fallback Upstreams

`upstream_servers` is a flat list used when no pool matches or as a global fallback. It uses `default_strategy` for resolution.

```toml
[dns]
upstream_servers = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
]
default_strategy = "Parallel"
```

For most deployments, pools with explicit priorities are preferable to a flat `upstream_servers` list — they give you more control over failover behavior.

---

## Query Timeout

```toml
[dns]
query_timeout = 3   # seconds
```

If an upstream does not respond within `query_timeout` seconds, the query is considered failed for that server and the next server in the strategy is tried (for `Failover`) or the response is returned from whichever server answered first (for `Parallel` and `Balanced`).

---

## Recommended Configurations

### Home / Small Office

Fast encrypted DNS with a plain UDP safety net:

```toml
[dns]
query_timeout    = 3
dnssec_mode      = "Permissive"
default_strategy = "Parallel"

[[dns.pools]]
name     = "secure"
strategy = "Parallel"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[[dns.pools]]
name     = "fallback"
strategy = "Failover"
priority = 2
servers  = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
]

[dns.health_check]
interval          = 30
timeout           = 2000
failure_threshold = 3
success_threshold = 2
```

### High-Throughput / Enterprise

Balanced load across multiple providers with automatic failover:

```toml
[dns]
query_timeout    = 2
dnssec_mode      = "Permissive"
default_strategy = "Balanced"

[[dns.pools]]
name     = "primary"
strategy = "Balanced"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "tls://1.1.1.1:853",
    "tls://8.8.8.8:853",
]

[[dns.pools]]
name     = "emergency"
strategy = "Failover"
priority = 2
servers  = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
    "udp://9.9.9.9:53",
]

[dns.health_check]
interval          = 15
timeout           = 1000
failure_threshold = 2
success_threshold = 1
```

### Internal Network (Split DNS)

Route internal domains to a local resolver, everything else to DoH:

```toml
[dns]
query_timeout    = 3
local_domain     = "corp"
local_dns_server = "10.0.0.10:53"   # internal AD/DNS server

[[dns.pools]]
name     = "public"
strategy = "Parallel"
priority = 1
servers  = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]
```

Internal domain routing (e.g. `corp.internal` → `10.0.0.10:53`) is configured via **Clients > Groups > Forwarding** in the dashboard.

---

## Public Resolver Reference

For a complete list of public resolvers with DoH, DoT, and DoQ URLs, see [Encrypted DNS — Public Resolver Reference](encrypted-dns.md#configuring-upstreams).
