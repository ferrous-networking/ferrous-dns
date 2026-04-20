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
| `default_strategy` | `"Parallel"` | Default strategy for `upstream_servers`: `"Parallel"`, `"Balanced"`, or `"Failover"` |
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

## Rate Limiting {#rate-limiting}

Token-bucket rate limiting per client subnet protects against query floods and DoS attacks.

```toml
[dns.rate_limit]
enabled                    = true
queries_per_second         = 1000
burst_size                 = 500
ipv4_prefix_len            = 24
ipv6_prefix_len            = 48
whitelist                  = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
nxdomain_per_second        = 50
slip_ratio                 = 2
dry_run                    = false
stale_entry_ttl_secs       = 300
tcp_max_connections_per_ip = 30
dot_max_connections_per_ip = 15
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `false` | Master switch — `false` disables all rate limiting with zero overhead |
| `queries_per_second` | `1000` | Sustained token refill rate per subnet per second |
| `burst_size` | `500` | Token bucket capacity — allows short bursts above `queries_per_second` |
| `ipv4_prefix_len` | `24` | IPv4 prefix length for subnet grouping (e.g. 24 = /24) |
| `ipv6_prefix_len` | `48` | IPv6 prefix length for subnet grouping (e.g. 48 = /48) |
| `whitelist` | `[]` | CIDRs that bypass rate limiting entirely |
| `nxdomain_per_second` | `50` | Separate, stricter budget for NXDOMAIN responses per subnet |
| `slip_ratio` | `0` | Every Nth rate-limited UDP response sends TC=1 (forcing TCP retry). 0 = disabled |
| `dry_run` | `false` | Log rate-limit events without refusing queries |
| `stale_entry_ttl_secs` | `300` | Seconds before an idle subnet bucket is evicted from memory |
| `tcp_max_connections_per_ip` | `30` | Max concurrent TCP DNS connections per IP. 0 = unlimited |
| `dot_max_connections_per_ip` | `15` | Max concurrent DoT connections per IP. 0 = unlimited |

!!! tip "Tuning for your network"
    For a typical household (~100 devices), the defaults work well. The `whitelist` should include your local networks to avoid rate-limiting internal traffic. Use `dry_run = true` to validate thresholds before enforcing.

See [Security > Rate Limiting](../features/security.md#rate-limiting) for detailed explanations of each feature.

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

```text
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

```text
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

---

## DNS Tunneling Detection

DNS tunneling detection is configured under `[dns.tunneling_detection]`. It is enabled by default and requires no additional setup.

For full documentation including real-world attack examples, configuration reference, confidence scoring, and whitelisting, see the [Malware Detection](../features/malware-detection.md) page.

```toml title="ferrous-dns.toml"
[dns.tunneling_detection]
enabled                    = true
action                     = "block"
max_fqdn_length            = 120
max_label_length           = 50
block_null_queries         = true
entropy_threshold          = 3.8
query_rate_per_apex        = 50
unique_subdomain_threshold = 30
txt_proportion_threshold   = 0.05
nxdomain_ratio_threshold   = 0.20
confidence_threshold       = 0.7
stale_entry_ttl_secs       = 300
domain_whitelist           = []
client_whitelist           = []
```

---

## DGA Detection

DGA (Domain Generation Algorithm) detection analyzes second-level domain names for statistical properties associated with algorithmically generated names. It is **enabled by default** and requires no external feeds.

For full documentation including signal descriptions, malware family examples, and whitelisting, see the [Malware Detection](../features/malware-detection.md#dga-detection) page.

```toml title="ferrous-dns.toml"
[dns.dga_detection]
enabled                       = true
action                        = "block"
hot_path_confidence_threshold = 0.40
sld_entropy_threshold         = 3.5
sld_max_length                = 24
consonant_ratio_threshold     = 0.75
digit_ratio_threshold         = 0.30
ngram_score_threshold         = 0.6
dga_rate_per_client           = 10
confidence_threshold          = 0.65
stale_entry_ttl_secs          = 300
domain_whitelist              = []
client_whitelist              = []
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `true` | Master switch for DGA detection |
| `action` | `block` | Action when a DGA domain is detected: `block` (REFUSED) or `alert` (log only) |
| `hot_path_confidence_threshold` | `0.40` | Minimum weighted mini-score for Phase 1 hot-path detection (0.0–1.0). Typically requires 2+ signals to fire, preventing false positives on legitimate domains |
| `sld_entropy_threshold` | `3.5` | Shannon entropy of the SLD in bits/char — above this indicates a random-looking name |
| `sld_max_length` | `24` | Maximum SLD length — longer names trigger the length signal |
| `consonant_ratio_threshold` | `0.75` | Fraction of consonant characters — DGA names often lack vowels |
| `digit_ratio_threshold` | `0.30` | Fraction of digit characters — DGA algorithms frequently embed numbers |
| `ngram_score_threshold` | `0.6` | Bigram deviation score above this indicates non-human-readable character sequences |
| `dga_rate_per_client` | `10` | Maximum DGA-like domains per minute per client subnet |
| `confidence_threshold` | `0.65` | Minimum combined weighted score for Phase 2 background analysis to flag an SLD (0.0–1.0) |
| `stale_entry_ttl_secs` | `300` | Seconds before idle tracking entries are evicted from memory |
| `domain_whitelist` | `[]` | Domains that bypass DGA detection entirely |
| `client_whitelist` | `[]` | Client CIDRs (e.g. `10.0.0.0/8`) that bypass DGA detection |

---

## Response IP Filtering

Response IP filtering downloads C2 IP threat feeds and blocks DNS responses that resolve to known command-and-control server IPs. It is **disabled by default** because it requires configuring external feed URLs.

For full documentation including real-world examples, recommended feeds, and edge cases, see the [Malware Detection](../features/malware-detection.md#response-ip-filtering) page.

```toml title="ferrous-dns.toml"
[dns.response_ip_filter]
enabled                = false      # opt-in (requires feed URLs)
action                 = "block"    # "alert" | "block"
ip_list_urls = [
    # "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    # "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
]
refresh_interval_secs  = 86400      # 24 hours
ip_ttl_secs            = 604800     # 7 days
```

---

## DNS Cookies (RFC 7873)

DNS Cookies (RFC 7873) protect UDP-based DNS against two classes of attack: **source-IP spoofing** (an attacker forging queries from a victim's address) and **amplification** (an attacker using open resolvers to flood a target with large DNS responses). By exchanging a cryptographically verified token on every query/response pair, the server can distinguish legitimate clients from forged traffic before spending resources on resolution.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Master switch — enables DNS Cookie processing |
| `server_secret` | `str` | `""` | Hex-encoded 32-byte HMAC secret (64 hex chars). Empty = auto-generate an ephemeral secret on startup (not suitable for production) |
| `secret_rotation_secs` | `int` | `3600` | Seconds between secret rotations. The previous secret is still accepted for one full rotation window to allow in-flight clients to re-negotiate without errors |
| `require_valid_cookie` | `bool` | `false` | Strict mode — reject queries with an absent or invalid server cookie with `REFUSED` + EDE 25. Default `false` = permissive mode (always respond, but echo a fresh server cookie) |

### Permissive mode (default)

All queries are answered regardless of cookie status. The server always echoes a fresh HMAC-SHA256 server cookie in every response, so RFC-7873-capable clients learn and cache the cookie automatically.

```toml
[dns_cookies]
enabled               = true
server_secret         = ""
secret_rotation_secs  = 3600
require_valid_cookie  = false
```

### Strict mode

Queries that arrive without a valid server cookie are rejected immediately, before any upstream lookup is performed.

```toml
[dns_cookies]
enabled               = true
server_secret         = "a1b2c3d4e5f6..."   # 64 hex chars (32 bytes)
secret_rotation_secs  = 3600
require_valid_cookie  = true
```

!!! warning "Strict mode may break legacy clients"
    Setting `require_valid_cookie = true` will reject queries from DNS clients that do not implement RFC 7873 (older resolvers, some embedded devices, and certain monitoring tools). Enable strict mode only after verifying that all clients on your network support DNS Cookies, or use permissive mode (`require_valid_cookie = false`) as a safe default.

!!! tip "Persistent secret across restarts"
    When `server_secret` is empty, Ferrous DNS generates an ephemeral secret at startup. Clients that cached a server cookie during the previous run will need to re-negotiate on restart. For stable production deployments, set a fixed 64-character hex secret.

See [Security > DNS Cookies](../features/security.md#dns-cookies) for a full explanation of the handshake and threat model.
