# Configuration Overview

Ferrous DNS is configured via a TOML file and/or environment variables. Environment variables always take precedence over the config file.

---

## Configuration File

Pass the config file path at startup:

```bash
# Binary
./ferrous-dns --config /etc/ferrous-dns/ferrous-dns.toml

# Docker (env var)
FERROUS_CONFIG=/data/config/ferrous-dns.toml
```

If no config file is provided, Ferrous DNS starts with built-in defaults and is fully functional for basic DNS forwarding.

---

## Deployment Profiles

Pick the profile that matches your hardware. Copy, paste, and adjust the values marked with `# ← change this`.

---

### Raspberry Pi / Embedded (≤ 1 GB RAM, 4 cores)

Designed for Raspberry Pi 3/4/Zero 2W, Orange Pi, GL.iNet routers, and any device with 512 MB–1 GB of RAM. Prioritizes low memory use and reduced write pressure on the SD card.

```toml
# ── Server ────────────────────────────────────────────────────────────────────

[server]
dns_port     = 53
web_port     = 8080
bind_address = "0.0.0.0"

# ── DNS ───────────────────────────────────────────────────────────────────────

[dns]
query_timeout    = 5
dnssec_enabled   = false          # disable for ~20% lower cache-miss latency on ARM
block_private_ptr = true
block_non_fqdn   = true
local_domain     = "lan"
local_dns_server = "192.168.1.1:53"   # ← your router IP

# ── Cache ─────────────────────────────────────────────────────────────────────

cache_enabled                  = true
cache_ttl                      = 7200
cache_min_ttl                  = 300
cache_max_ttl                  = 86400
cache_max_entries              = 25000     # ~12 MB RAM
cache_eviction_strategy        = "lru"    # cheaper to compute on low-power CPUs
cache_compaction_interval      = 900
cache_batch_eviction_percentage = 0.15
cache_shard_amount             = 16       # 4 cores × 4

# Optimistic refresh — disabled on Pi to save CPU and upstream traffic
cache_optimistic_refresh = false

# ── Upstream Pools ────────────────────────────────────────────────────────────

[[dns.pools]]
name     = "primary"
strategy = "Failover"             # Failover is cheaper than Parallel on ARM
priority = 1
servers  = [
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
interval          = 60            # less frequent probes to save CPU
timeout           = 3000
failure_threshold = 3
success_threshold = 2

# ── Rate Limiting ────────────────────────────────────────────────────────────

[dns.rate_limit]
enabled                = true
queries_per_second     = 200     # conservative — RPi has limited CPU
burst_size             = 100
nxdomain_per_second    = 20
slip_ratio             = 2
whitelist              = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
tcp_max_connections_per_ip = 16
dot_max_connections_per_ip = 8

# ── Blocking ──────────────────────────────────────────────────────────────────

[blocking]
enabled = true

# ── Logging ───────────────────────────────────────────────────────────────────

[logging]
level = "warn"                    # reduce log noise on constrained devices

# ── Database ──────────────────────────────────────────────────────────────────

[database]
path              = "/data/ferrous-dns.db"   # ← use external USB drive if possible
log_queries       = true
queries_log_stored = 7            # 7 days — less disk usage

# SD card friendly: reduce write frequency
query_log_channel_capacity    = 2000
query_log_max_batch_size      = 500
query_log_flush_interval_ms   = 1000       # flush every 1s instead of 200ms
query_log_sample_rate         = 5          # log 1 in 5 queries — less I/O
query_log_pool_max_connections = 1

write_pool_max_connections = 1
read_pool_max_connections  = 3
write_busy_timeout_secs    = 30
read_busy_timeout_secs     = 15
read_acquire_timeout_secs  = 15

wal_autocheckpoint        = 0
wal_checkpoint_interval_secs = 300        # checkpoint every 5min instead of 2min
sqlite_cache_size_kb      = 4096          # 4 MB SQLite page cache
sqlite_mmap_size_mb       = 16
```

!!! tip "SD card longevity"
    Move the database to a USB drive or a `tmpfs` mount to reduce SD card writes. See the [Database configuration](database.md) for SD card tuning options.

---

### Home Server / Mini PC (2–8 GB RAM, 4–8 cores)

Suitable for dedicated home servers, Intel NUCs, Beelink / Minisforum mini PCs, and Docker hosts. This is the baseline recommended configuration.

```toml
# ── Server ────────────────────────────────────────────────────────────────────

[server]
dns_port     = 53
web_port     = 8080
bind_address = "0.0.0.0"

# ── Authentication ────────────────────────────────────────────────────────────

[auth]
enabled = true

[auth.admin]
username = "admin"
password_hash = ""                       # ← set via setup wizard on first run

# ── DNS ───────────────────────────────────────────────────────────────────────

[dns]
query_timeout     = 3
dnssec_enabled    = true
block_private_ptr = true
block_non_fqdn    = true
local_domain      = "lan"
local_dns_server  = "192.168.1.1:53"   # ← your router IP

# ── Cache ─────────────────────────────────────────────────────────────────────

cache_enabled                   = true
cache_ttl                       = 7200
cache_min_ttl                   = 300
cache_max_ttl                   = 86400
cache_max_entries               = 100000    # ~50 MB RAM
cache_eviction_strategy         = "hit_rate"
cache_compaction_interval       = 600
cache_batch_eviction_percentage = 0.10
# cache_shard_amount auto-detected (4 × CPU cores)

# Optimistic refresh — keeps hot entries from ever expiring
cache_optimistic_refresh    = true
cache_refresh_threshold     = 0.75
cache_min_hit_rate          = 2.0
cache_min_frequency         = 10
cache_access_window_secs    = 43200

# LFU-K
cache_min_lfuk_score    = 1.5
cache_lfuk_history_size = 10

# ── Upstream Pools ────────────────────────────────────────────────────────────

[[dns.pools]]
name     = "encrypted"
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

# ── Rate Limiting ────────────────────────────────────────────────────────────

[dns.rate_limit]
enabled                = true
queries_per_second     = 1000    # ~10 QPS/device, covers heavy browsing + IoT
burst_size             = 500     # absorbs page loads (50+ queries/page)
nxdomain_per_second    = 50
slip_ratio             = 2       # 50% TC=1 for rate-limited traffic
whitelist              = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
tcp_max_connections_per_ip = 30
dot_max_connections_per_ip = 15

# ── Blocking ──────────────────────────────────────────────────────────────────

[blocking]
enabled = true

# ── Logging ───────────────────────────────────────────────────────────────────

[logging]
level = "info"

# ── Database ──────────────────────────────────────────────────────────────────

[database]
path              = "/data/ferrous-dns.db"
log_queries       = true
queries_log_stored = 30

query_log_channel_capacity    = 10000
query_log_max_batch_size      = 2000
query_log_flush_interval_ms   = 200
query_log_sample_rate         = 1       # log all queries
query_log_pool_max_connections = 2

write_pool_max_connections = 3
read_pool_max_connections  = 8
write_busy_timeout_secs    = 30
read_busy_timeout_secs     = 15
read_acquire_timeout_secs  = 15

wal_autocheckpoint           = 0
wal_checkpoint_interval_secs = 120
sqlite_cache_size_kb         = 16384    # 16 MB SQLite page cache
sqlite_mmap_size_mb          = 64
```

---

### High-Performance Server (16+ GB RAM, 8+ cores)

For environments handling thousands of clients simultaneously: enterprise networks, ISP edge, high-density multi-tenant setups. Maximizes throughput and cache capacity.

```toml
# ── Server ────────────────────────────────────────────────────────────────────

[server]
dns_port     = 53
web_port     = 8080
bind_address = "0.0.0.0"

# ── Authentication ────────────────────────────────────────────────────────────

[auth]
enabled = true
session_ttl_hours = 8                     # shorter sessions for production
login_rate_limit_attempts = 3             # stricter rate limiting

[auth.admin]
username = "admin"
password_hash = ""                        # ← set via setup wizard on first run

# ── DNS ───────────────────────────────────────────────────────────────────────

[dns]
query_timeout     = 2             # tighter timeout — upstreams must be fast
dnssec_enabled    = true
block_private_ptr = true
block_non_fqdn    = true
local_domain      = "corp"
local_dns_server  = "10.0.0.1:53"    # ← internal DNS / DHCP server

# ── Cache ─────────────────────────────────────────────────────────────────────

cache_enabled                   = true
cache_ttl                       = 7200
cache_min_ttl                   = 60            # allow shorter TTLs for dynamic content
cache_max_ttl                   = 86400
cache_max_entries               = 500000        # ~250 MB RAM
cache_eviction_strategy         = "hit_rate"
cache_compaction_interval       = 300           # compact every 5min
cache_batch_eviction_percentage = 0.05          # smaller batches, more frequent
cache_shard_amount              = 256           # explicit — 16-core × 16
cache_adaptive_thresholds       = true          # auto-tune eviction thresholds

# Aggressive optimistic refresh for near-100% hit rate
cache_optimistic_refresh    = true
cache_refresh_threshold     = 0.80             # refresh earlier (80% TTL consumed)
cache_min_hit_rate          = 1.0              # lower threshold — refresh more entries
cache_min_frequency         = 5               # fewer hits required
cache_access_window_secs    = 86400           # 24h access window

# LFU-K
cache_min_lfuk_score    = 1.0
cache_lfuk_history_size = 20                  # track 20 access timestamps per entry

# ── Upstream Pools ────────────────────────────────────────────────────────────

[[dns.pools]]
name     = "primary"
strategy = "Balanced"             # distribute load across all upstreams
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
interval          = 15            # more frequent monitoring
timeout           = 1000
failure_threshold = 2             # fail fast
success_threshold = 1             # restore fast

# ── Rate Limiting ────────────────────────────────────────────────────────────

[dns.rate_limit]
enabled                = true
queries_per_second     = 50      # strict per-subnet limits for public-facing
burst_size             = 100
nxdomain_per_second    = 10      # aggressive NX budget against DGA/random subdomain
slip_ratio             = 2
ipv4_prefix_len        = 24
ipv6_prefix_len        = 48
whitelist              = []      # no exemptions on public resolvers
tcp_max_connections_per_ip = 30
dot_max_connections_per_ip = 15

# ── Blocking ──────────────────────────────────────────────────────────────────

[blocking]
enabled = true

# ── Logging ───────────────────────────────────────────────────────────────────

[logging]
level = "warn"                    # reduce log volume at scale

# ── Database ──────────────────────────────────────────────────────────────────

[database]
path              = "/data/ferrous-dns.db"
log_queries       = true
queries_log_stored = 90           # 3 months retention

query_log_channel_capacity    = 200000          # large buffer for burst traffic
query_log_max_batch_size      = 5000
query_log_flush_interval_ms   = 100             # flush more frequently
query_log_sample_rate         = 1               # log all (or set to 10 for very high QPS)
query_log_pool_max_connections = 4

write_pool_max_connections = 5
read_pool_max_connections  = 20
write_busy_timeout_secs    = 30
read_busy_timeout_secs     = 10
read_acquire_timeout_secs  = 10

wal_autocheckpoint           = 0
wal_checkpoint_interval_secs = 60              # checkpoint every minute
sqlite_cache_size_kb         = 65536           # 64 MB SQLite page cache
sqlite_mmap_size_mb          = 512
```

!!! tip "Build flags for max performance"
    On dedicated x86_64 hardware, always build with:
    ```bash
    RUSTFLAGS="-C target-cpu=native" cargo build --release
    ```
    This enables AVX2 vectorization and CPU-specific branch prediction. The difference is measurable.

---

## Full Configuration Reference

Complete annotated TOML with all available options and their defaults.

```toml
# ── Server ────────────────────────────────────────────────────────────────────

[server]
dns_port     = 53                           # UDP/TCP port for DNS queries
web_port     = 8080                         # HTTP port for the dashboard and REST API
bind_address = "0.0.0.0"                    # Listen on all interfaces
# cors_allowed_origins = ["*"]              # CORS origins for the REST API
# pihole_compat = false                     # Pi-hole v6 compatible API at /api/*
# proxy_protocol_enabled = false            # PROXY Protocol v2 on TCP/DoT listeners

# ── Authentication ────────────────────────────────────────────────────────────

[auth]
enabled = true                              # Enable authentication globally
session_ttl_hours = 24                      # Session lifetime without "Remember Me"
remember_me_days = 30                       # Session lifetime with "Remember Me"
login_rate_limit_attempts = 5               # Max failed attempts before lockout
login_rate_limit_window_secs = 900          # Lockout window (15 min)

[auth.admin]
username = "admin"                          # Admin username
password_hash = ""                          # Argon2id hash (set via setup wizard or CLI)

# ── Encrypted DNS ─────────────────────────────────────────────────────────────

# [server.encrypted_dns]
# dot_enabled   = true
# dot_port      = 853
# doh_enabled   = true
# doh_port      = 443                       # omit to co-host on web_port
# tls_cert_path = "/data/cert.pem"
# tls_key_path  = "/data/key.pem"

# ── DNS Resolution ────────────────────────────────────────────────────────────

[dns]
upstream_servers = []                       # Fallback upstreams when no pool matches
query_timeout    = 3                        # Seconds to wait for upstream response
default_strategy = "Parallel"              # "Parallel" or "Sequential"
dnssec_enabled   = true                    # Validate DNSSEC signatures
block_private_ptr = true                   # Block PTR lookups for RFC-1918 ranges
block_non_fqdn   = true                    # Block non-FQDN queries
local_domain     = "lan"                   # Local domain suffix
local_dns_server = "10.0.0.1:53"           # Router — PTR/hostname/upstream resolution

# ── Cache ─────────────────────────────────────────────────────────────────────

cache_enabled                   = true
cache_ttl                       = 7200
cache_min_ttl                   = 300
cache_max_ttl                   = 86400
cache_max_entries               = 200000
cache_eviction_strategy         = "hit_rate"    # "hit_rate", "lfu", or "lru"
cache_compaction_interval       = 600
cache_batch_eviction_percentage = 0.1
cache_adaptive_thresholds       = false
# cache_shard_amount = 512                  # auto: 4 × CPU cores, rounded to power of 2

# Optimistic Refresh
cache_optimistic_refresh    = true
cache_refresh_threshold     = 0.75
cache_min_hit_rate          = 2.0
cache_min_frequency         = 10
cache_access_window_secs    = 43200

# LFU-K Eviction
cache_min_lfuk_score    = 1.5
cache_lfuk_history_size = 10

# ── Upstream Pools ────────────────────────────────────────────────────────────

[[dns.pools]]
name     = "pool1"
strategy = "Parallel"
priority = 1
servers  = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

# ── Health Checks ─────────────────────────────────────────────────────────────

[dns.health_check]
interval          = 30
timeout           = 2000
failure_threshold = 3
success_threshold = 2

# ── Rate Limiting ────────────────────────────────────────────────────────────

[dns.rate_limit]
enabled                    = false      # master switch
queries_per_second         = 1000       # sustained QPS per subnet
burst_size                 = 500        # token bucket capacity
ipv4_prefix_len            = 24         # /24 = class C network
ipv6_prefix_len            = 48         # /48 = standard home delegation
whitelist                  = [          # bypass rate limiting
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
nxdomain_per_second        = 50         # stricter NXDOMAIN budget
slip_ratio                 = 0          # TC=1 slip frequency (0 = disabled)
dry_run                    = false      # true = log only, don't enforce
stale_entry_ttl_secs       = 300        # idle bucket eviction
tcp_max_connections_per_ip = 30         # TCP connection limit per IP
dot_max_connections_per_ip = 15         # DoT connection limit per IP

# ── Local DNS Records ─────────────────────────────────────────────────────────

[[dns.local_records]]
hostname    = "server"
domain      = "local"
ip          = "192.168.1.100"
record_type = "A"
ttl         = 300

# ── Blocking ──────────────────────────────────────────────────────────────────

[blocking]
enabled        = true
custom_blocked = []                         # Additional domains to block
whitelist      = []                         # Domains to always allow

# ── Logging ───────────────────────────────────────────────────────────────────

[logging]
level = "info"                              # "error", "warn", "info", "debug", "trace"

# ── Database ──────────────────────────────────────────────────────────────────

[database]
path                    = "ferrous-dns.db"
log_queries             = true
queries_log_stored      = 30               # Days to retain query logs
client_tracking_interval = 60             # Seconds between client last-seen updates

# Write Pipeline
query_log_channel_capacity    = 10000
query_log_max_batch_size      = 2000
query_log_flush_interval_ms   = 200
query_log_sample_rate         = 1          # 1 = log all; 10 = log 1 in 10
client_channel_capacity       = 4096

# Connection Pools
write_pool_max_connections    = 3
read_pool_max_connections     = 8
query_log_pool_max_connections = 2
write_busy_timeout_secs       = 30
read_busy_timeout_secs        = 15
read_acquire_timeout_secs     = 15

# SQLite Tuning
wal_autocheckpoint           = 0
wal_checkpoint_interval_secs = 120
sqlite_cache_size_kb         = 16384
sqlite_mmap_size_mb          = 64
```

---

## Section Reference

| Section | Description |
|:--------|:------------|
| [`[server]`](server.md) | Ports, bind address, Pi-hole compat |
| [`[auth]`](server.md#authentication) | Authentication, sessions, API tokens, rate limiting |
| [`[server.encrypted_dns]`](server.md#encrypted-dns) | DoT and DoH server-side listeners |
| [`[dns]`](dns.md) | Upstream resolution, DNSSEC, local records |
| [`[[dns.pools]]`](dns.md#upstream-pools) | Upstream server groups and strategies |
| [`[dns.health_check]`](dns.md#health-checks) | Upstream health monitoring |
| [`[dns.rate_limit]`](rate-limiting.md) | Token bucket rate limiting, NXDOMAIN budget, TC=1 slip, connection limits |
| [`[dns]` local_dns_server](dns.md#local-dns-server) | PTR lookups, DHCP, upstream hostname resolution |
| [`cache_*`](cache.md) | L1/L2 cache tuning, eviction, refresh |
| [`[blocking]`](blocking.md) | Ad-blocking, allowlist, custom rules |
| [`[logging]`](database.md) | Log verbosity |
| [`[database]`](database.md) | SQLite path, query log, write pipeline, tuning |
