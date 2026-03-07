# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-07 20:14:46 UTC
> Tool: dnsperf 2.14.0 | Duration: 60s per server | Clients: 10 concurrent | Query dataset: 187 domains (A, AAAA, MX, TXT, NS)

---

## Test Environment

| | |
|:--|:--|
| **Host OS** | Arch Linux — Kernel 6.12.75-1-lts x86\_64 |
| **CPU** | Intel Core i9-9900KF @ 3.60GHz — 8 cores / 16 threads |
| **RAM** | 46 GB |
| **Scheduler** | PREEMPT\_DYNAMIC |

---

## Docker Config (identical for all servers)

| Setting | Value |
|:--------|:------|
| CPUs | `cpuset: 0-15` — 16 threads |
| Network | host mode |
| Upstreams | plain UDP `8.8.8.8` / `1.1.1.1` (parallel) |
| Cache | enabled |
| Blocking / denylists | **disabled** — isolates raw DNS forwarding performance |
| Rate limiting | **disabled** |
| Log level | info |
| Query logging (disk I/O) | **disabled** |

---

## Per-Server Configuration

### 🦀 Ferrous-DNS

| Key setting | Value |
|:------------|:------|
| Port | 5353 |
| Upstream strategy | `Parallel` (fastest wins) |
| Cache max entries | 200,000 |
| Cache eviction | `hit_rate` (LFU-K sliding window) |
| Cache shards | 512 (DashMap) |
| Optimistic prefetch | enabled |
| DNSSEC | disabled |
| Query log | disabled (`log_queries = false`) |
| Blocking engine | disabled (`blocking.enabled = false`) |
| Allocator | mimalloc |
| Async runtime | Tokio |

### ⚡ Unbound (C)

| Key setting | Value |
|:------------|:------|
| Port | 5356 |
| Threads | 16 (`num-threads: 16`) |
| SO\_REUSEPORT | enabled |
| Cache | enabled — msg-cache 256 MB, rrset-cache 512 MB |
| Cache TTL | min 300s / max 86400s |
| Upstream strategy | forward-zone `.` → `8.8.8.8`, `1.1.1.1` |
| Rate limiting | disabled (`ratelimit: 0`) |
| Verbosity | 1 (info) |

### ⚡ PowerDNS Recursor (C++)

| Key setting | Value |
|:------------|:------|
| Port | 5358 |
| Threads | 16 |
| Record cache | 200,000 entries |
| Packet cache | 200,000 entries |
| Upstream strategy | forward-zones-recurse `.` → `8.8.8.8`, `1.1.1.1` |
| DNSSEC | disabled (`validation: off`) |
| Log level | 5 (info) |

### 🔷 Blocky (Go)

| Key setting | Value |
|:------------|:------|
| Port | 5357 |
| GOMAXPROCS | 16 |
| Upstream strategy | `parallel_best` (fastest wins) |
| Cache | enabled — min 5m / max 24h |
| Prefetching | enabled |
| Denylists | none (blocking disabled) |
| Query log | disabled (`type: none`) |
| Log level | info |

### 🛡️ AdGuard Home (Go)

| Key setting | Value |
|:------------|:------|
| Port | 5355 |
| GOMAXPROCS | 16 |
| Upstreams | `8.8.8.8`, `1.1.1.1` |
| Cache | enabled |
| Blocking | disabled |
| Log level | info |

### 🕳️ Pi-hole

| Key setting | Value |
|:------------|:------|
| Port | 5354 |
| Upstreams | `8.8.8.8`, `1.1.1.1` |
| dnsmasq cache-size | 10,000 entries |
| Rate limiting | disabled (`rateLimit.count = 0`) |
| DNSSEC | disabled |
| Blocking | not configured |

---

## Results

| Server | QPS | Avg Lat | P99 Lat | Completed | Lost |
|:-------|----:|--------:|--------:|----------:|-----:|
| ⚡ Unbound (C) | 952,810 | 0.98ms | 2.19ms | 99.81% | 0.19% |
| ⚡ PowerDNS (C++) | 884,128 | 2.06ms | 15.68ms | 99.82% | 0.18% |
| 🦀 **Ferrous-DNS** | **482,506** | **1.19ms** | **13.32ms** | **99.60%** | **0.40%** |
| 🔷 Blocky (Go) | 101,747 | 82.83ms | 206.78ms | 99.69% | 0.31% |
| 🛡️ AdGuard Home | 97,627 | 3.82ms | 15.27ms | 98.06% | 1.94% |
| 🕳️ Pi-hole | 2,066 | 46.43ms | 562.34ms | 51.00% | 49.00% |

**Ferrous-DNS vs competitors:** 4.9× faster than AdGuard Home | 4.7× faster than Blocky | 233× faster than Pi-hole

Unbound and PowerDNS Recursor lead as purpose-built pure recursive resolvers (C and C++) with no REST API, no Web UI, no database, and no blocking engine. Ferrous-DNS runs all of these in the same single-process binary.

---

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
- **Query dataset**: `bench/data/queries.txt` — 187 domains (A, AAAA, MX, TXT, NS mix)
- **Workload**: all servers receive the same query dataset in loop mode
- **Warm-up**: 5s warm-up run before each 60s measurement window
- **P99**: estimated from dnsperf output as `avg + 2.33 × stddev` (normal distribution approximation)
- **Isolation**: each server benchmarked sequentially; competitors stopped between runs

---

## How to Reproduce

```bash
# Prerequisites
apt install dnsperf     # Debian/Ubuntu
pacman -S dnsperf       # Arch Linux
brew install dnsperf    # macOS

# Run the full benchmark suite
cd /path/to/Ferrous-DNS
bash bench/benchmark.sh --duration 60 --clients 10 --output bench/benchmark-results.md

# Custom Ferrous-DNS address (if running externally)
FERROUS_DNS_ADDR=192.168.1.10:5353 bash bench/benchmark.sh
```
