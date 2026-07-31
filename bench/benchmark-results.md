# ferrous-dns — Performance Benchmark Results

> Generated: 2026-07-13 UTC — **median of 3 runs**
> Per run: 60s dataset looped, 45s measured/server | 10 clients
> Server pinned to cores 0-7, dnsperf pinned to cores 8-15 (isolated load generator)

## Results

Median QPS across 3 runs. This is a **cache-hit forwarding** benchmark: every
server has its cache enabled and forwards to `8.8.8.8` / `1.1.1.1`, so Unbound
and PowerDNS Recursor run in forward mode rather than recursing from the root.
The table measures how fast each server answers from its own cache — not
recursive resolution performance.

| Server             | Median QPS | Median Avg Lat | QPS spread (min–max) |
|:-------------------|-----------:|:--------------:|:---------------------|
| 🦀 **ferrous-dns** |    899,234 |         0.86ms | 886,953 – 1,019,534  |
| ⚡ Unbound (C)      |    816,928 |         0.85ms | 633,167 – 822,635    |
| ⚡ PowerDNS (C++)   |    675,910 |         1.36ms | 659,487 – 722,406    |
| 🔷 Blocky          |    142,715 |         1.53ms | 142,473 – 144,368    |
| 🛡️ AdGuard Home    |     88,985 |         3.81ms | 87,448 – 98,437      |
| 🕳️ Pi-hole         |      8,248 |         2.99ms | 7,219 – 8,939        |

**ferrous-dns, Unbound and PowerDNS Recursor land in the same performance
tier.** The spread between the three sits inside run-to-run variance on this
host, so read the top of the table as a tie, not a ranking. The distance to the
feature-comparable servers is not in doubt: 6.3× Blocky, 10.1× AdGuard Home,
109× Pi-hole. Unbound and PowerDNS are purpose-built pure recursive resolvers
with no REST API, no Web UI, no database and no blocking engine; ferrous-dns
keeps pace with them while running a full feature stack (DNS server, REST API,
Web UI, SQLite query log, blocking engine) in a single process.

> **Read the median, not a single run.** Run-to-run variance on this host is real
> (~10–15% for ferrous-dns, up to ~30% for Unbound, which had one low outlier).
> With 3 samples and a gap that size, the ordering of the top three is not
> statistically meaningful — ferrous-dns did come out ahead in all 3 runs, but
> that is not presented as a lead. Pi-hole's ~2% loss rate reflects its
> architectural ceiling: FTL v6 is mostly single-threaded and cannot use more than
> one core regardless of the CPU budget.

---

## Test Machine

| | |
|---|---|
| **CPU** | Intel Core i9-9900KF @ 3.60 GHz |
| **Cores / Threads** | 8 cores / 16 threads (1 socket) |
| **L3 Cache** | 16 MiB |
| **RAM** | 46 GiB |
| **OS** | Arch Linux |
| **Kernel** | 7.0.10-zen1-1-zen |
| **Allocator** | mimalloc (ferrous-dns) |
| **Build flags** | `RUSTFLAGS="-C target-cpu=native"` |

CPU isolation: the harness splits the host cores in half. Every server-under-test
runs pinned to `cpuset: 0-7` with a `cpus: 8` quota (identical budget for all);
dnsperf runs pinned to cores `8-15` so the load generator never steals CPU from
the server it is measuring.

---

## Server Configurations

All servers are configured for a fair comparison:
- Same upstreams: `8.8.8.8` and `1.1.1.1` (plain UDP)
- Blocking disabled — isolates raw DNS forwarding + caching performance
- Query logging disabled — no I/O overhead during measurement (all servers)
- Rate limiting disabled — lets dnsperf saturate each server
- DNSSEC disabled — plain UDP upstreams don't validate
- Thread count matched to the 8-core cpuset (see per-server notes)

### 🦀 ferrous-dns v0.9.2

| Setting | Value |
|---|---|
| Upstreams | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (Parallel strategy) |
| Cache | Enabled — 200,000 entries, `hit_rate` eviction, 512 shards |
| Cache TTL | min 300s / max 86400s / default 7200s |
| Inflight shards | 64 |
| Optimistic refresh | Enabled (`threshold=0.75`, `min_hit_rate=2.0`) |
| Blocking | Disabled |
| Query logging | Disabled (`log_queries = false`, now honored on the hot path) |
| Rate limiting | Disabled |
| DNSSEC | Disabled |
| Workers | 8 Tokio workers, one pinned per allowed core (auto-detected from cpuset) |

### ⚡ Unbound (latest)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` (forward-zone) |
| Threads | 8 (matches server cpuset) |
| Cache | `msg-cache-size: 256m`, `rrset-cache-size: 512m` |
| Cache TTL | min 300s / max 86400s |
| Rate limiting | Disabled (`ratelimit: 0`) |
| DNSSEC | Disabled |

### ⚡ PowerDNS Recursor (v5)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` (forward-zones-recurse) |
| Threads | 8 (matches server cpuset) |
| Record cache | 200,000 entries |
| Packet cache | 200,000 entries |
| DNSSEC | Off (`validation: "off"`) |
| Log level | 5 (per-query logging suppressed via default `quiet`) |

### 🔷 Blocky (latest)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` (strategy: `parallel_best`) |
| Cache | `minTime: 5m`, `maxTime: 24h`, `prefetching: true` |
| Blocking | Disabled (no denylists) |
| Query logging | Disabled (`queryLog.type: none`) |
| GOMAXPROCS | 8 (matches server cpuset) |

### 🛡️ AdGuard Home (latest)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` |
| Listen port | 5359 (5355 is LLMNR — held by systemd-resolved on this host) |
| Cache | 16 MiB |
| Rate limiting | Disabled (`ratelimit: 0`) |
| Protection | Disabled (`protection_enabled: false`) |
| Query logging | Disabled (`querylog.enabled: false`) |
| GOMAXPROCS | 8 (matches server cpuset) |

### 🕳️ Pi-hole v6 (FTL v6)

| Setting | Value |
|---|---|
| Upstreams | `8.8.8.8`, `1.1.1.1` |
| Cache | 10,000 entries |
| Rate limiting | Disabled (`rateLimit.count: 0`) |
| Query logging | Disabled (`queryLogging: false`) |
| Threads | single-threaded by architecture (dnsmasq/FTL — no thread knob) |
| DNSSEC | Disabled |

---

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
- **Query dataset**: `bench/data/queries.txt` — 187 unique queries (mix of A, AAAA, MX, TXT, NS), looped for the full duration
- **Runs**: benchmark executed 3 times end-to-end; the table reports the **median** QPS/latency per server, plus the min–max spread for transparency
- **Warm-up**: 5s warm-up before each measurement
- **In-flight cap**: `-q 1000` (up to 1000 outstanding queries per client)
- **CPU isolation**: server pinned to cores 0-7, dnsperf pinned to cores 8-15; all servers run simultaneously but each is benchmarked sequentially
- **Fairness**: identical upstreams, caches warmed the same way, logging/rate-limiting/DNSSEC off for everyone, and thread counts matched to the 8-core cpuset

## How to reproduce

```bash
# Install dnsperf
apt install dnsperf    # Debian/Ubuntu
pacman -S dnsperf      # Arch Linux
brew install dnsperf   # macOS

# Build the ferrous-dns release binary first (the bench image copies it in)
RUSTFLAGS="-C target-cpu=native" cargo build --release -p ferrous-dns
docker compose -f bench/docker-compose.yml build ferrous-dns

# Run the benchmark (brings each server up, measures, tears down)
./bench/benchmark.sh --output bench/benchmark-results.md

# Shorter run for quick iteration
./bench/benchmark.sh --duration 30 --clients 10
```
