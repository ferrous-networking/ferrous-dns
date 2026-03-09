# Rate Limiting Configuration

The `[dns.rate_limit]` section configures per-subnet token-bucket rate limiting and per-IP connection limits for TCP/DoT.

---

## Overview

Ferrous DNS rate limiting protects against DNS query floods and DoS attacks while allowing legitimate traffic through. It works at three levels:

1. **Query rate limiting** — token bucket per client subnet (UDP + TCP)
2. **NXDOMAIN budget** — separate stricter limit for non-existent domain responses
3. **Connection limiting** — per-IP caps on concurrent TCP and DoT connections

When disabled (`enabled = false`), rate limiting adds zero overhead to query processing.

---

## Full Configuration

```toml title="ferrous-dns.toml"
[dns.rate_limit]
enabled                    = true       # master switch
queries_per_second         = 1000       # sustained QPS per subnet
burst_size                 = 500        # token bucket capacity
ipv4_prefix_len            = 24         # /24 = class C network
ipv6_prefix_len            = 48         # /48 = standard home delegation
whitelist                  = [          # bypass rate limiting
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]
nxdomain_per_second        = 50         # stricter NXDOMAIN budget
slip_ratio                 = 2          # TC=1 slip frequency
dry_run                    = false      # true = log only
stale_entry_ttl_secs       = 300        # idle bucket eviction
tcp_max_connections_per_ip = 30         # TCP connection limit
dot_max_connections_per_ip = 15         # DoT connection limit
```

---

## Token Bucket Algorithm

Each client subnet gets an independent token bucket:

- Tokens refill at `queries_per_second` rate
- Maximum capacity is `burst_size`
- Each query consumes one token
- When empty, queries are either refused or slipped (TC=1)

```text
Subnet 10.0.0.0/24:
  [==========------]  burst_size = 500
       ↑ 350 tokens remaining

  Refill: +1000 tokens/sec (capped at 500)
  Consume: -1 token per query
```

!!! info "Subnet grouping"
    All clients within the same subnet share a single bucket. With `ipv4_prefix_len = 24`, all devices in `192.168.1.0/24` share one bucket. This prevents a single device from consuming the entire budget.

---

## Reference

### Query Rate Limiting

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Master switch. When `false`, all rate limiting is bypassed with zero overhead |
| `queries_per_second` | `u32` | `1000` | Token refill rate per subnet per second |
| `burst_size` | `u32` | `500` | Token bucket capacity. Allows short bursts (e.g. page loads generating 50+ queries) |
| `ipv4_prefix_len` | `u8` | `24` | IPv4 prefix length. `24` groups a `/24` subnet. Range: 8–32 |
| `ipv6_prefix_len` | `u8` | `48` | IPv6 prefix length. `48` covers a standard home delegation. Range: 16–64 |
| `whitelist` | `[str]` | `[]` | List of CIDRs that bypass rate limiting entirely |
| `nxdomain_per_second` | `u32` | `50` | Separate budget for NXDOMAIN responses. Catches random-subdomain attacks |
| `slip_ratio` | `u32` | `0` | Every Nth rate-limited response is TC=1 instead of REFUSED. `0` = disabled |
| `dry_run` | `bool` | `false` | Log rate-limit events without refusing queries |
| `stale_entry_ttl_secs` | `u64` | `300` | Seconds before an idle subnet bucket is evicted from memory |

### Connection Limiting

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `tcp_max_connections_per_ip` | `u32` | `30` | Max concurrent TCP DNS connections per IP address. `0` = unlimited |
| `dot_max_connections_per_ip` | `u32` | `15` | Max concurrent DoT connections per IP address. `0` = unlimited |

---

## TC=1 Slip

When `slip_ratio > 0`, Ferrous DNS alternates between REFUSED and TC=1 (truncated) responses for rate-limited queries:

| `slip_ratio` | Behavior |
|:-------------|:---------|
| `0` | All rate-limited responses are REFUSED |
| `1` | All rate-limited responses are TC=1 |
| `2` | Every 2nd rate-limited response is TC=1, rest are REFUSED |
| `N` | Every Nth rate-limited response is TC=1 |

TC=1 forces clients to retry over TCP, which:

- **Verifies legitimacy** — spoofed-source floods can't complete TCP handshakes
- **Allows recovery** — real clients still get answers via TCP
- **Follows standards** — same approach used by NSD and BIND

---

## NXDOMAIN Budget

The NXDOMAIN budget is a separate, stricter token bucket that only applies to queries resulting in NXDOMAIN responses. This catches:

- **Random subdomain attacks** — bots generating `abc123.example.com` queries
- **IoT scanning** — devices probing many non-existent subdomains
- **DGA malware** — domain generation algorithm traffic

The NXDOMAIN burst capacity is `nxdomain_per_second * 2`. The general query budget is not affected by NXDOMAIN traffic.

---

## Dry-Run Mode

With `dry_run = true`:

- Rate-limited queries are **allowed** through (not refused)
- Events are logged with status `RATE_LIMITED` in the query log
- The dashboard shows rate-limited counts in the stats card and timeline
- Useful for calibrating thresholds before enforcing

---

## Whitelist

CIDRs in the `whitelist` bypass rate limiting entirely. Both IPv4 and IPv6 CIDRs are supported:

```toml
whitelist = [
    "127.0.0.0/8",       # loopback
    "::1/128",           # IPv6 loopback
    "10.0.0.0/8",        # private class A
    "172.16.0.0/12",     # private class B
    "192.168.0.0/16",    # private class C
]
```

!!! tip "Home network setup"
    Whitelist your RFC-1918 subnets to avoid rate-limiting internal traffic. Rate limiting is primarily meant for external or untrusted networks.

---

## Tuning Guide

### Household (~100 devices)

```toml
[dns.rate_limit]
enabled                = true
queries_per_second     = 1000    # ~10 QPS/device, covers heavy browsing + IoT
burst_size             = 500     # absorbs page loads (50+ queries/page)
nxdomain_per_second    = 50      # IoT devices probe many subdomains
slip_ratio             = 2       # 50% TC=1 for rate-limited traffic
whitelist              = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

### Small office (~20 devices)

```toml
[dns.rate_limit]
enabled                = true
queries_per_second     = 200
burst_size             = 100
nxdomain_per_second    = 20
slip_ratio             = 2
```

### Public resolver

```toml
[dns.rate_limit]
enabled                = true
queries_per_second     = 50      # strict per-subnet limits
burst_size             = 100
nxdomain_per_second    = 10
slip_ratio             = 2
ipv4_prefix_len        = 24
ipv6_prefix_len        = 48
whitelist              = []      # no exemptions
```

---

## Dashboard Integration

When rate limiting is enabled:

- The **Dashboard** shows a "Rate Limited" stat card with the count of throttled queries
- The **Timeline chart** includes a third dataset (amber) for rate-limited queries over time
- The **Query Log** shows rate-limited queries with an orange badge and supports filtering by "Rate Limited" category
- The **Settings** page provides a full UI for configuring all rate limiting options

---

## Performance

The rate limiter is designed for the DNS hot path with zero-allocation per-query checks:

- **DashMap** with `FxBuildHasher` for sharded concurrent access
- **AtomicU64** with `Ordering::Relaxed` for lock-free token operations
- **SubnetKey(u64)** — register-sized key with zero heap allocation
- **CLOCK_MONOTONIC_COARSE** timestamps (~5ns vs ~25ns for `Instant::now()`)
- Background eviction task removes idle buckets every `stale_entry_ttl_secs`

When `enabled = false`, the rate limiter returns immediately with zero overhead.
