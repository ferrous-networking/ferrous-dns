# ferrous-dns — Performance Benchmark Results

> Generated: 2026-03-11 17:13:40 UTC
> Duration per server: 60s | Clients: 10 | Queries: 187

## Results

| Server             |    QPS     | Avg Lat    |  P99 Lat   | Completed   | Lost       |
|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|
| 🦀 ferrous-dns   | 511,413 |     1.89ms |    47.50ms |       100.00% |       0.00% |
| ⚡ Unbound        | 1,018,691 |     0.74ms |     2.05ms |       100.00% |       0.00% |
| ⚡ PowerDNS (C++) | 797,600 |     1.11ms |     3.47ms |       100.00% |       0.00% |
| 🔷 Blocky        | 98,574 |     9.49ms |    21.39ms |        99.99% |       0.01% |
| 🛡️  AdGuard Home | 97,808 |     3.90ms |    15.59ms |        99.87% |       0.13% |
| 🕳️  Pi-hole      | 558 |     2.55ms |    24.83ms |        73.63% |      26.37% |

> Pi-hole's loss rate reflects its architectural ceiling: FTL v6 is mostly
> single-threaded and saturates under concurrent load from other containers
> sharing the same CPU pool.

---

## Test Machine

| | |
|---|---|
| **CPU** | Intel Core i9-9900KF @ 3.60 GHz |
| **Cores / Threads** | 8 cores / 16 threads (1 socket) |
| **L3 Cache** | 16 MiB |
| **RAM** | 46 GiB |
| **OS** | Arch Linux |
| **Kernel** | 6.18.16-1-lts |
| **Allocator** | mimalloc (ferrous-dns) |
| **Build flags** | `RUSTFLAGS="-C target-cpu=native"` |

All containers share `cpuset: "0-15"` and `cpus: '16'` via Docker — same CPU budget for all.

---

## Server Configurations

All servers are configured for a fair comparison:
- Same upstreams: `8.8.8.8` and `1.1.1.1` (plain UDP)
- Blocking disabled — isolates raw DNS forwarding + caching performance
- Query logging disabled — no I/O overhead during measurement
- Rate limiting disabled — lets dnsperf saturate each server
- DNSSEC disabled — plain UDP upstreams don't validate

### 🦀 ferrous-dns v0.7.0

| Setting | Value |
|---|---|
| Upstreams | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (Parallel strategy) |
| Cache | Enabled — 200,000 entries, `hit_rate` eviction, 512 shards |
| Cache TTL | min 300s / max 86400s / default 7200s |
| Inflight shards | 64 |
| Optimistic refresh | Enabled (`threshold=0.75`, `min_hit_rate=2.0`) |
| Blocking | Disabled |
| Query logging | Disabled |
| Rate limiting | Disabled |
| DNSSEC | Disabled |
| Tunneling / DGA detection | Disabled |

### ⚡ Unbound (latest)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` (forward-zone) |
| Threads | 16 |
| Cache | `msg-cache-size: 256m`, `rrset-cache-size: 512m` |
| Cache TTL | min 300s / max 86400s |
| Rate limiting | Disabled (`ratelimit: 0`) |
| DNSSEC | Disabled |

### ⚡ PowerDNS Recursor (master)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` (forward-zones-recurse) |
| Threads | 16 |
| Record cache | 200,000 entries |
| Packet cache | 200,000 entries |
| DNSSEC | Off (`validation: "off"`) |
| Log level | 5 (info) |

### 🔷 Blocky (latest)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` (strategy: `parallel_best`) |
| Cache | `minTime: 5m`, `maxTime: 24h`, `prefetching: true` |
| Blocking | Disabled (no denylists) |
| Query logging | Disabled (`queryLog.type: none`) |
| GOMAXPROCS | 16 |

### 🛡️ AdGuard Home (latest)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` |
| Cache | 16 MiB |
| Rate limiting | Disabled (`ratelimit: 0`) |
| Protection | Disabled (`protection_enabled: false`) |
| Query logging | Disabled |
| GOMAXPROCS | 16 |

### 🕳️ Pi-hole v6 (FTL v6.5)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` |
| Cache | 10,000 entries |
| Rate limiting | Disabled (`rateLimit.count: 0`) |
| Query logging | Disabled (`queryLogging: false`) |
| CNAME deep inspect | Disabled |
| DNSSEC | Disabled |
| Listening mode | ALL |

---

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) v2.14.0 by DNS-OARC
- **Query dataset**: `bench/data/queries.txt` — 187 unique queries (mix of A, AAAA, MX, TXT, NS), looped for the full duration
- **Workload**: All servers use the same query dataset in loop mode
- **Warm-up**: 5s warm-up before each measurement
- **In-flight cap**: `-q 1000` (100 outstanding queries per client)
- **P99**: Estimated from `avg + 2.33 × σ` (dnsperf provides average + stddev)
- **Isolation**: All containers run simultaneously sharing the same CPU pool; each server is benchmarked sequentially

## How to reproduce

```bash
# Install dnsperf
apt install dnsperf    # Debian/Ubuntu
pacman -S dnsperf      # Arch Linux
brew install dnsperf   # macOS

# Run benchmark (ferrous-dns must be running first)
./bench/benchmark.sh --output bench/benchmark-results.md

# With custom ferrous-dns address
FERROUS_DNS_ADDR=192.168.1.10:53 ./bench/benchmark.sh

# Shorter run for quick iteration
./bench/benchmark.sh --duration 30 --clients 10
```
