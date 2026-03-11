# `ferrous-dns.toml` Reference

Complete annotated reference for every option in `ferrous-dns.toml`. For deployment-ready starting points, see the [Configuration Overview](index.md).

---

## Loading the Config File

```bash
ferrous-dns --config path/to/ferrous-dns.toml
```

Or via environment variable:

```bash
FERROUS_CONFIG=path/to/ferrous-dns.toml ferrous-dns
```

!!! info "All sections are optional"
    Every section and every key has a built-in default. You only need to include what you want to override.

---

## Quick Reference {#quick-reference}

| Section | Purpose | Detail |
|:--------|:--------|:-------|
| [`[server]`](#server) | Ports, bind address, Pi-hole compat, PROXY Protocol | [Server config](server.md) |
| [`[server.web_tls]`](#web-tls) | HTTPS for the web dashboard and REST API | [Server config](server.md#web-tls) |
| [`[server.encrypted_dns]`](#encrypted-dns) | DoT and DoH server-side listeners | [Encrypted DNS](../features/encrypted-dns.md) |
| [`[auth]`](#auth) | Session authentication for dashboard and API | [Security](../features/security.md) |
| [`[auth.admin]`](#auth-admin) | Admin username and password hash | [Security](../features/security.md) |
| [`[dns]`](#dns) | Upstream fallback, timeouts, DNSSEC, privacy controls | [DNS & Upstreams](dns.md) |
| [`[[dns.pools]]`](#pools) | Named upstream server pools with strategy and priority | [Upstream Management](../features/upstream-management.md) |
| [`[dns.health_check]`](#health-check) | Probes to detect and evict unhealthy upstreams | [Upstream Management](../features/upstream-management.md) |
| [`[dns]` cache keys](#cache) | L1/L2 cache, eviction, and optimistic refresh | [Cache configuration](cache.md) |
| [`[dns.rate_limit]`](#rate-limit) | Token bucket rate limiter per client subnet | [Rate Limiting](rate-limiting.md) |
| [`[dns.tunneling_detection]`](#tunneling-detection) | Two-phase DNS tunneling detector | [Malware Detection](../features/malware-detection.md#tunneling-detection) |
| [`[dns.dga_detection]`](#dga-detection) | Domain Generation Algorithm detector | [Malware Detection](../features/malware-detection.md#dga-detection) |
| [`[dns.nxdomain_hijack]`](#nxdomain-hijack) | ISP NXDOMAIN hijack detection and reversal | [Malware Detection](../features/malware-detection.md#nxdomain-hijack) |
| [`[dns.response_ip_filter]`](#response-ip-filter) | Block responses resolving to known C2 IPs | [Malware Detection](../features/malware-detection.md#response-ip-filter) |
| [`[[dns.local_records]]`](#local-records) | Static A/AAAA records with auto-PTR | [DNS & Upstreams](dns.md#local-records) |
| [`[blocking]`](#blocking) | Ad and malware blocking via blocklists | [Blocking & Filtering](../features/blocking-filtering.md) |
| [`[logging]`](#logging) | Log level | — |
| [`[database]`](#database) | SQLite persistence, query log pipeline, connection pools | [Database configuration](database.md) |

---

## `[server]` {#server}

Controls which ports and interfaces Ferrous DNS listens on, and enables optional compatibility and protocol features.

```toml title="ferrous-dns.toml"
[server]
dns_port                 = 53
web_port                 = 8080
bind_address             = "0.0.0.0"
pihole_compat            = false
proxy_protocol_enabled   = false
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `dns_port` | `int` | `53` | UDP and TCP port for DNS queries |
| `web_port` | `int` | `8080` | HTTP/HTTPS port for the dashboard and REST API |
| `bind_address` | `str` | `"0.0.0.0"` | Network interface to bind to; `0.0.0.0` listens on all interfaces |
| `pihole_compat` | `bool` | `false` | Expose Pi-hole v6 compatible API at `/api/*`; Ferrous DNS native API moves to `/ferrous/api/*` |
| `proxy_protocol_enabled` | `bool` | `false` | Enable PROXY Protocol v2 on TCP DNS and DoT listeners |

!!! warning "PROXY Protocol"
    Only enable `proxy_protocol_enabled` when a trusted load balancer always sits in front of Ferrous DNS. Without a load balancer, all TCP DNS connections will be rejected because the server expects a PROXY Protocol header on every connection.

See [Server configuration](server.md).

---

## `[server.web_tls]` {#web-tls}

Enables HTTPS for the web dashboard and REST API. When `enabled = true`, HTTPS is served on `web_port` with automatic redirect from plain HTTP. If the cert or key files are absent at startup, the server logs a warning and falls back to plain HTTP.

```toml title="ferrous-dns.toml"
[server.web_tls]
enabled       = false
tls_cert_path = "/data/cert.pem"
tls_key_path  = "/data/key.pem"
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Enable HTTPS for the web server |
| `tls_cert_path` | `str` | `"/data/cert.pem"` | Path to the PEM-encoded TLS certificate |
| `tls_key_path` | `str` | `"/data/key.pem"` | Path to the PEM-encoded TLS private key |

!!! warning "Docker paths"
    When running in Docker, `tls_cert_path` and `tls_key_path` must point to paths accessible from inside the container. Mount the certificate directory as a volume.

---

## `[server.encrypted_dns]` {#encrypted-dns}

Enables DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) server-side listeners. This section is commented out by default. If the cert or key files are missing at startup, the affected listeners are skipped with a warning; plain DNS continues normally.

```toml title="ferrous-dns.toml"
[server.encrypted_dns]
dot_enabled   = false
dot_port      = 853
doh_enabled   = false
# doh_port    = 443           # omit to co-host DoH on web_port
tls_cert_path = "/data/cert.pem"
tls_key_path  = "/data/key.pem"
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `dot_enabled` | `bool` | `false` | Enable DNS-over-TLS listener |
| `dot_port` | `int` | `853` | TCP port for DoT (RFC 7858 standard: 853) |
| `doh_enabled` | `bool` | `false` | Enable the `/dns-query` DoH endpoint |
| `doh_port` | `int` | — | Dedicated HTTPS port for DoH; omit to co-host on `web_port` |
| `tls_cert_path` | `str` | `"/data/cert.pem"` | Path to the PEM-encoded TLS certificate |
| `tls_key_path` | `str` | `"/data/key.pem"` | Path to the PEM-encoded TLS private key |

See [Encrypted DNS](../features/encrypted-dns.md).

---

## `[auth]` {#auth}

Authentication settings for the dashboard and REST API. When `enabled = false`, all endpoints are publicly accessible without credentials.

```toml title="ferrous-dns.toml"
[auth]
enabled                      = true
session_ttl_hours            = 24
remember_me_days             = 30
login_rate_limit_attempts    = 5
login_rate_limit_window_secs = 900
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable or disable authentication globally |
| `session_ttl_hours` | `int` | `24` | Default session lifetime in hours (without "Remember Me") |
| `remember_me_days` | `int` | `30` | Extended session lifetime in days with "Remember Me" |
| `login_rate_limit_attempts` | `int` | `5` | Max failed login attempts before lockout |
| `login_rate_limit_window_secs` | `int` | `900` | Lockout window duration in seconds (15 min) |

---

## `[auth.admin]` {#auth-admin}

Admin credentials. The `password_hash` field stores an Argon2id hash. When left empty, Ferrous DNS presents a setup wizard on first access.

```toml title="ferrous-dns.toml"
[auth.admin]
username      = "admin"
password_hash = ""
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `username` | `str` | `"admin"` | Admin username |
| `password_hash` | `str` | `""` | Argon2id hash; empty string triggers the setup wizard on first run |

!!! tip "Setting the password"
    Set the admin password via the web setup wizard on first run, or reset it at any time with the `--reset-password` CLI flag. The Argon2id hash is written back to the config file automatically.

See [Security](../features/security.md).

---

## `[dns]` {#dns}

Core DNS resolver options: upstream fallback, timeouts, DNSSEC validation, local domain handling, and privacy controls. Cache options also live under `[dns]` and are documented in the [Cache keys](#cache) section below.

```toml title="ferrous-dns.toml"
[dns]
upstream_servers  = []
query_timeout     = 3
default_strategy  = "Parallel"
dnssec_enabled    = true
block_private_ptr = true
block_non_fqdn    = true
local_domain      = "lan"
local_dns_server  = "10.0.0.1:53"
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `upstream_servers` | `list` | `[]` | Fallback upstream servers used when no pool matches; supports all URI schemes |
| `query_timeout` | `int` | `3` | Seconds to wait for an upstream response before trying the next server |
| `default_strategy` | `str` | `"Parallel"` | Default resolution strategy for `upstream_servers`: `"Parallel"` or `"Sequential"` |
| `dnssec_enabled` | `bool` | `true` | Validate DNSSEC signatures on upstream responses |
| `block_private_ptr` | `bool` | `true` | Block PTR lookups for private/RFC-1918 IP ranges |
| `block_non_fqdn` | `bool` | `true` | Block queries for non-fully-qualified domain names |
| `local_domain` | `str` | `"lan"` | Local domain suffix appended to short hostnames |
| `local_dns_server` | `str` | `"10.0.0.1:53"` | Router or DHCP server used for PTR lookups and client hostname resolution |

See [DNS & Upstreams](dns.md).

---

## `[[dns.pools]]` {#pools}

Named upstream server pools. Multiple pools are selected by priority order; the pool with the lowest `priority` value is tried first. Each pool specifies its own resolution strategy independently of `default_strategy`.

```toml title="ferrous-dns.toml"
[[dns.pools]]
name     = "cloudflare"
strategy = "Parallel"
priority = 1
servers  = [
    "https://cloudflare-dns.com/dns-query",
    "https://1.1.1.1/dns-query",
]

[[dns.pools]]
name     = "google"
strategy = "Failover"
priority = 2
servers  = [
    "tls://8.8.8.8:853",
    "tls://8.8.4.4:853",
]
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `name` | `str` | — | Pool identifier used in logs and the dashboard |
| `strategy` | `str` | `"Parallel"` | Resolution strategy: `"Parallel"`, `"Balanced"`, or `"Failover"` |
| `priority` | `int` | `1` | Pool priority; lower value = higher priority |
| `servers` | `list` | `[]` | List of upstream server URIs |

!!! info "Supported URI schemes"
    ```
    udp://8.8.8.8:53                          Plain UDP
    tcp://8.8.8.8:53                          Plain TCP
    tls://1.1.1.1:853                         DNS-over-TLS
    https://cloudflare-dns.com/dns-query      DNS-over-HTTPS
    doq://dns.adguard-dns.com:853             DNS-over-QUIC
    h3://dns.google/dns-query                 HTTP/3
    ```

See [Upstream Management](../features/upstream-management.md).

---

## `[dns.health_check]` {#health-check}

Periodic probes that detect and remove unhealthy upstream servers from the active pool. A server is marked unhealthy after `failure_threshold` consecutive failed probes, and restored after `success_threshold` consecutive successes.

```toml title="ferrous-dns.toml"
[dns.health_check]
interval           = 30
timeout            = 2000
failure_threshold  = 3
success_threshold  = 2
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `interval` | `int` | `30` | Seconds between probes per server |
| `timeout` | `int` | `2000` | Milliseconds to wait for a probe response |
| `failure_threshold` | `int` | `3` | Consecutive failures before marking a server unhealthy |
| `success_threshold` | `int` | `2` | Consecutive successes required to restore a server to healthy status |

---

## Cache keys under `[dns]` {#cache}

These keys live directly under `[dns]` (not a sub-table). They configure the L1/L2 in-memory DNS cache, eviction strategy, and optimistic background refresh.

### Basic cache options

```toml title="ferrous-dns.toml"
[dns]
cache_enabled                    = true
cache_ttl                        = 7200
cache_min_ttl                    = 300
cache_max_ttl                    = 86400
cache_max_entries                = 200000
cache_eviction_strategy          = "hit_rate"
cache_compaction_interval        = 600
cache_batch_eviction_percentage  = 0.1
cache_adaptive_thresholds        = false
# cache_shard_amount             = 512
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `cache_enabled` | `bool` | `true` | Enable the DNS response cache |
| `cache_ttl` | `int` | `7200` | Default TTL in seconds when an upstream record carries none |
| `cache_min_ttl` | `int` | `300` | Minimum TTL; records with lower TTLs are clamped to this value |
| `cache_max_ttl` | `int` | `86400` | Maximum TTL; records with higher TTLs are clamped |
| `cache_max_entries` | `int` | `200000` | Maximum number of entries in the L2 cache |
| `cache_eviction_strategy` | `str` | `"hit_rate"` | Eviction policy: `"hit_rate"`, `"lfu"`, or `"lru"` |
| `cache_compaction_interval` | `int` | `600` | Seconds between compaction runs that remove expired entries |
| `cache_batch_eviction_percentage` | `float` | `0.1` | Fraction of the cache evicted in one pass when full (0.1 = 10%) |
| `cache_adaptive_thresholds` | `bool` | `false` | Auto-tune eviction thresholds based on observed hit rates |
| `cache_shard_amount` | `int` | auto | L2 cache shard count; auto = 4 x CPU cores rounded up to next power of 2 |

### Optimistic refresh

Background refresh renews popular entries before they expire, keeping the cache hit rate high without cold misses.

```toml title="ferrous-dns.toml"
[dns]
cache_optimistic_refresh  = true
cache_refresh_threshold   = 0.75
cache_min_hit_rate        = 2.0
cache_min_frequency       = 10
cache_access_window_secs  = 43200
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `cache_optimistic_refresh` | `bool` | `true` | Enable background refresh for popular entries |
| `cache_refresh_threshold` | `float` | `0.75` | Schedule a refresh when this fraction of the original TTL has been consumed |
| `cache_min_hit_rate` | `float` | `2.0` | Minimum hits per minute for an entry to qualify for refresh |
| `cache_min_frequency` | `int` | `10` | Minimum total hits before an entry is eligible for refresh |
| `cache_access_window_secs` | `int` | `43200` | Access window in seconds for refresh eligibility (43200 = 12 hours) |

### LFU-K eviction parameters

Used when `cache_eviction_strategy` is `"hit_rate"` or `"lfu"`.

```toml title="ferrous-dns.toml"
[dns]
cache_min_lfuk_score     = 1.5
cache_lfuk_history_size  = 10
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `cache_min_lfuk_score` | `float` | `1.5` | Minimum LFU-K score threshold for eviction candidates |
| `cache_lfuk_history_size` | `int` | `10` | Number of recent access timestamps tracked per entry |

See [Cache configuration](cache.md).

---

## `[dns.rate_limit]` {#rate-limit}

Token bucket rate limiter applied per client subnet. Protects against query floods without impacting normal traffic. Separate budgets are enforced for NXDOMAIN-heavy clients.

```toml title="ferrous-dns.toml"
[dns.rate_limit]
enabled                    = true
queries_per_second         = 1000
burst_size                 = 500
ipv4_prefix_len            = 24
ipv6_prefix_len            = 48
whitelist                  = []
nxdomain_per_second        = 50
slip_ratio                 = 2
dry_run                    = false
tcp_max_connections_per_ip = 30
dot_max_connections_per_ip = 15
stale_entry_ttl_secs       = 300
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable the rate limiter |
| `queries_per_second` | `int` | `1000` | Sustained query budget per client subnet |
| `burst_size` | `int` | `500` | Maximum burst above the sustained rate |
| `ipv4_prefix_len` | `int` | `24` | Group IPv4 clients by this prefix length (e.g. `/24` subnet) |
| `ipv6_prefix_len` | `int` | `48` | Group IPv6 clients by this prefix length (e.g. `/48` subnet) |
| `whitelist` | `list` | `[]` | CIDRs exempt from rate limiting |
| `nxdomain_per_second` | `int` | `50` | Stricter budget applied specifically to NXDOMAIN responses |
| `slip_ratio` | `int` | `2` | 1 in N rate-limited responses sends `TC=1` to force a TCP retry |
| `dry_run` | `bool` | `false` | Log rate limit events without enforcing them |
| `tcp_max_connections_per_ip` | `int` | `30` | Maximum concurrent TCP DNS connections per client IP |
| `dot_max_connections_per_ip` | `int` | `15` | Maximum concurrent DoT connections per client IP |
| `stale_entry_ttl_secs` | `int` | `300` | Seconds of inactivity before a token bucket entry is evicted |

See [Rate Limiting](rate-limiting.md).

---

## `[dns.tunneling_detection]` {#tunneling-detection}

Two-phase DNS tunneling detector. Phase 1 runs on the hot path in O(1) time, checking FQDN length, label length, and NULL query type. Phase 2 runs statistical analysis in the background (Shannon entropy, query rate, unique subdomains, record type proportions).

```toml title="ferrous-dns.toml"
[dns.tunneling_detection]
enabled                      = true
action                       = "block"
max_fqdn_length              = 120
max_label_length             = 50
block_null_queries           = true
entropy_threshold            = 3.8
query_rate_per_apex          = 50
unique_subdomain_threshold   = 30
txt_proportion_threshold     = 0.05
nxdomain_ratio_threshold     = 0.20
confidence_threshold         = 0.7
stale_entry_ttl_secs         = 300
domain_whitelist             = []
client_whitelist             = []
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable tunneling detection |
| `action` | `str` | `"block"` | Action on detection: `"alert"`, `"block"`, or `"throttle"` |
| `max_fqdn_length` | `int` | `120` | Phase 1: FQDNs longer than this are blocked immediately |
| `max_label_length` | `int` | `50` | Phase 1: labels longer than this are blocked immediately |
| `block_null_queries` | `bool` | `true` | Phase 1: block NULL (type 10) queries |
| `entropy_threshold` | `float` | `3.8` | Phase 2: Shannon entropy in bits/char above which a domain is flagged |
| `query_rate_per_apex` | `int` | `50` | Phase 2: queries per minute per client+apex pair above which a domain is flagged |
| `unique_subdomain_threshold` | `int` | `30` | Phase 2: unique subdomains per minute before flagging |
| `txt_proportion_threshold` | `float` | `0.05` | Phase 2: TXT query proportion above 5% triggers a flag |
| `nxdomain_ratio_threshold` | `float` | `0.20` | Phase 2: NXDOMAIN ratio above 20% triggers a flag |
| `confidence_threshold` | `float` | `0.7` | Phase 2: minimum combined confidence score (0–1) required to act |
| `stale_entry_ttl_secs` | `int` | `300` | Seconds of inactivity before a tracking entry is evicted |
| `domain_whitelist` | `list` | `[]` | Domains exempt from tunneling detection |
| `client_whitelist` | `list` | `[]` | Client CIDRs exempt from tunneling detection |

See [Malware Detection](../features/malware-detection.md#tunneling-detection).

---

## `[dns.dga_detection]` {#dga-detection}

Detects Domain Generation Algorithm domains used by malware families such as Conficker, Mirai, and Emotet. Phase 1 runs weighted mini-scoring on the hot path (entropy, consonant ratio, digit ratio, length). Phase 2 runs n-gram language model scoring in the background.

```toml title="ferrous-dns.toml"
[dns.dga_detection]
enabled                       = true
action                        = "block"
hot_path_confidence_threshold = 0.40
sld_entropy_threshold         = 3.5
sld_max_length                = 24
consonant_ratio_threshold     = 0.75
digit_ratio_threshold         = 0.3
ngram_score_threshold         = 0.6
dga_rate_per_client           = 10
confidence_threshold          = 0.65
stale_entry_ttl_secs          = 300
domain_whitelist              = []
client_whitelist              = []
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable DGA detection |
| `action` | `str` | `"block"` | Action on detection: `"alert"` or `"block"` |
| `hot_path_confidence_threshold` | `float` | `0.40` | Phase 1: hot-path score threshold; typically requires 2 or more signals |
| `sld_entropy_threshold` | `float` | `3.5` | Shannon entropy of the second-level domain |
| `sld_max_length` | `int` | `24` | Maximum SLD character length before the domain is considered suspicious |
| `consonant_ratio_threshold` | `float` | `0.75` | Consonant fraction of the SLD above which the domain is flagged |
| `digit_ratio_threshold` | `float` | `0.3` | Digit fraction of the SLD above which the domain is flagged |
| `ngram_score_threshold` | `float` | `0.6` | Phase 2: n-gram language model score threshold |
| `dga_rate_per_client` | `int` | `10` | DGA-flagged queries per minute per client before action is escalated |
| `confidence_threshold` | `float` | `0.65` | Phase 2: minimum combined confidence score required to act |
| `stale_entry_ttl_secs` | `int` | `300` | Seconds of inactivity before a tracking entry is evicted |
| `domain_whitelist` | `list` | `[]` | Domains exempt from DGA detection |
| `client_whitelist` | `list` | `[]` | Client CIDRs exempt from DGA detection |

See [Malware Detection](../features/malware-detection.md#dga-detection).

---

## `[dns.nxdomain_hijack]` {#nxdomain-hijack}

Detects ISPs that intercept NXDOMAIN responses and substitute advertising IP addresses. Background probes test each upstream with random `.invalid` domains (RFC 6761). Discovered hijack IPs are recorded, and any hot-path response containing them is converted back to a proper NXDOMAIN.

```toml title="ferrous-dns.toml"
[dns.nxdomain_hijack]
enabled              = true
action               = "block"
probe_interval_secs  = 300
probe_timeout_ms     = 5000
probes_per_round     = 3
hijack_ip_ttl_secs   = 3600
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable NXDOMAIN hijack detection |
| `action` | `str` | `"block"` | `"alert"` to log only; `"block"` to convert hijacked responses back to NXDOMAIN |
| `probe_interval_secs` | `int` | `300` | Seconds between probe rounds per upstream server |
| `probe_timeout_ms` | `int` | `5000` | Milliseconds to wait for a probe response |
| `probes_per_round` | `int` | `3` | Number of probe queries sent per upstream per round |
| `hijack_ip_ttl_secs` | `int` | `3600` | Seconds before an unconfirmed hijack IP entry is evicted |

See [Malware Detection](../features/malware-detection.md#nxdomain-hijack).

---

## `[dns.response_ip_filter]` {#response-ip-filter}

Blocks DNS responses that resolve to known command-and-control server IP addresses. Downloads IP threat feeds and checks every DNS response. Disabled by default — opt-in.

```toml title="ferrous-dns.toml"
[dns.response_ip_filter]
enabled                 = false
action                  = "block"
ip_list_urls            = []
refresh_interval_secs   = 86400
ip_ttl_secs             = 604800
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Enable response IP filtering (opt-in) |
| `action` | `str` | `"block"` | `"alert"` to log only; `"block"` to return NXDOMAIN |
| `ip_list_urls` | `list` | `[]` | Feed URLs; one IP per line, `#` comments are supported |
| `refresh_interval_secs` | `int` | `86400` | Seconds between feed refreshes (24 hours) |
| `ip_ttl_secs` | `int` | `604800` | Seconds before an IP entry expires if not re-confirmed by a feed refresh (7 days) |

!!! tip "Example feeds"
    ```
    https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
    ```

See [Malware Detection](../features/malware-detection.md#response-ip-filter).

---

## `[[dns.local_records]]` {#local-records}

Static A or AAAA records served directly from the cache, bypassing upstream entirely. An automatic PTR record is generated for every A record.

```toml title="ferrous-dns.toml"
[[dns.local_records]]
hostname    = "nas"
domain      = "local"
ip          = "192.168.1.50"
record_type = "A"
ttl         = 300

[[dns.local_records]]
hostname    = "printer"
domain      = "local"
ip          = "192.168.1.51"
record_type = "A"
ttl         = 300
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `hostname` | `str` | — | Hostname without the domain suffix |
| `domain` | `str` | — | Domain suffix (e.g. `"local"`, `"lan"`) |
| `ip` | `str` | — | IP address for this record |
| `record_type` | `str` | `"A"` | Record type: `"A"` or `"AAAA"` |
| `ttl` | `int` | `300` | TTL in seconds |

See [DNS & Upstreams](dns.md#local-records).

---

## `[blocking]` {#blocking}

DNS-based ad and malware blocking using downloaded blocklists. Blocklists are managed through the dashboard. Custom per-domain overrides can be specified directly in the config.

```toml title="ferrous-dns.toml"
[blocking]
enabled        = true
custom_blocked = []
whitelist      = []
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable DNS blocking globally |
| `custom_blocked` | `list` | `[]` | Additional domains to block beyond any active blocklists |
| `whitelist` | `list` | `[]` | Domains that are always allowed, even if present in a blocklist |

See [Blocking & Filtering](../features/blocking-filtering.md).

---

## `[logging]` {#logging}

```toml title="ferrous-dns.toml"
[logging]
level = "info"
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `level` | `str` | `"info"` | Log verbosity: `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"` |

!!! info "`debug` and `trace` levels"
    `debug` and `trace` are verbose and should only be used for troubleshooting. They emit hot-path events on every DNS query and may measurably impact throughput on high-load deployments.

---

## `[database]` {#database}

SQLite persistence for query logs, client records, blocklists, groups, and settings. The write pipeline is fully async so disk I/O never blocks the DNS hot path.

### Basic options

```toml title="ferrous-dns.toml"
[database]
path                      = "ferrous-dns.db"
log_queries               = true
queries_log_stored        = 30
client_tracking_interval  = 60
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `path` | `str` | `"ferrous-dns.db"` | Path to the SQLite database file |
| `log_queries` | `bool` | `true` | Store every DNS query for analytics and the query log dashboard |
| `queries_log_stored` | `int` | `30` | Days to retain query log entries before automatic cleanup |
| `client_tracking_interval` | `int` | `60` | Minimum seconds between consecutive last-seen writes for the same client IP |

### Query-log write pipeline

```toml title="ferrous-dns.toml"
[database]
query_log_channel_capacity  = 10000
query_log_max_batch_size    = 2000
query_log_flush_interval_ms = 200
query_log_sample_rate       = 1
client_channel_capacity     = 4096
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `query_log_channel_capacity` | `int` | `10000` | Async channel buffer size in entries |
| `query_log_max_batch_size` | `int` | `2000` | Maximum entries per INSERT transaction |
| `query_log_flush_interval_ms` | `int` | `200` | Milliseconds between flush cycles |
| `query_log_sample_rate` | `int` | `1` | Log 1 out of every N queries; `1` = log all, `10` = log 1 in 10 |
| `client_channel_capacity` | `int` | `4096` | Async channel buffer size for client last-seen updates |

### Connection pools

```toml title="ferrous-dns.toml"
[database]
write_pool_max_connections       = 3
read_pool_max_connections        = 8
query_log_pool_max_connections   = 2
write_busy_timeout_secs          = 30
read_busy_timeout_secs           = 15
read_acquire_timeout_secs        = 15
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `write_pool_max_connections` | `int` | `3` | Maximum connections in the write pool |
| `read_pool_max_connections` | `int` | `8` | Maximum connections in the read pool |
| `query_log_pool_max_connections` | `int` | `2` | Maximum connections in the query-log write pool |
| `write_busy_timeout_secs` | `int` | `30` | Seconds to wait for the write lock before returning an error |
| `read_busy_timeout_secs` | `int` | `15` | Seconds to wait for a read connection before returning an error |
| `read_acquire_timeout_secs` | `int` | `15` | Seconds to wait to acquire a connection from the read pool |

### SQLite tuning

```toml title="ferrous-dns.toml"
[database]
wal_autocheckpoint             = 0
wal_checkpoint_interval_secs   = 120
sqlite_cache_size_kb           = 16384
sqlite_mmap_size_mb            = 64
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `wal_autocheckpoint` | `int` | `0` | SQLite WAL autocheckpoint threshold in pages; `0` disables automatic checkpointing (a background job manages it instead) |
| `wal_checkpoint_interval_secs` | `int` | `120` | Seconds between WAL PASSIVE checkpoint runs by the background job |
| `sqlite_cache_size_kb` | `int` | `16384` | SQLite page cache size in KB (default: 16 MB) |
| `sqlite_mmap_size_mb` | `int` | `64` | Memory-mapped I/O size in MB; `0` disables mmap |

See [Database configuration](database.md).
