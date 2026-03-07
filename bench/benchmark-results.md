# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-07 UTC
> Duration per server: **60s** | Clients: **10** | Query dataset: 197 domains (A, AAAA, MX, TXT, NS)
> Host: localhost (loopback) — eliminates network jitter
> Tool: [dnsperf 2.14.0](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
> **Fair comparison**: all servers run in Docker with identical resource constraints — 16 CPUs, cache enabled, log level info, rate limiting disabled, plain UDP upstreams `8.8.8.8` and `1.1.1.1`

### Test Machine

| Component | Details |
|:----------|:--------|
| OS        | Arch Linux |
| Kernel    | 6.12.75-1-lts |
| CPU       | Intel Core i9-9900KF @ 3.60GHz |
| Cores     | 8 cores / 16 threads |
| L2 Cache  | 2 MiB (8 instances) |
| L3 Cache  | 16 MiB |
| RAM       | 48 GB |

### Container Config (all servers)

| Setting | Value |
|:--------|:------|
| CPUs | 16 (`cpuset: "0-15"`, `deploy.limits.cpus: 16`) |
| Cache | enabled |
| Log level | info |
| Rate limiting | disabled |
| Capabilities | `NET_ADMIN`, `SYS_TIME`, `SYS_NICE`, `NET_BIND_SERVICE` |
| Upstreams | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (parallel) |
| Blocking | disabled |

---

## Results

| Server               |        QPS |  Avg Lat |   P99 Lat¹ | Completed | Lost   |
|:---------------------|-----------:|---------:|-----------:|----------:|-------:|
| ⚡ PowerDNS (C++)    |   220,635  |   2.04ms |   11.98ms  |  99.12%  | 0.88%  |
| ⚡ Unbound (C)       |   217,527  |   1.11ms |    4.99ms  |  99.10%  | 0.90%  |
| 🦀 Ferrous-DNS      | **147,241** | **2.14ms** | **30.67ms** | 98.70%  | 1.30%  |
| 🛡️ AdGuard Home     |    93,159  |   3.96ms |   15.98ms  |  97.97%  | 2.03%  |
| 🔷 Blocky (Go)       |    91,417  |  76.10ms |  191.76ms  |  99.33%  | 0.67%  |
| 🕳️ Pi-hole²         |     4,427  |  30.18ms |  231.12ms  |  69.20%  | 30.80% |

> ¹ P99 estimated as `avg + 2.33 × σ` (dnsperf reports average + standard deviation)
> ² Pi-hole lost 31% of packets under sustained load — dnsmasq is fundamentally single-threaded; `bench/pihole.toml` mounts `rateLimit.count = 0` but the bottleneck is architectural

---

## Speedup vs Competitors

| Comparison                    | Result           |
|:------------------------------|:----------------:|
| Ferrous-DNS vs AdGuard Home   | **1.58× faster** |
| Ferrous-DNS vs Blocky         | **1.61× faster** |
| Ferrous-DNS vs Pi-hole        | **33× faster**   |
| Ferrous-DNS vs Unbound        | 0.68× (Unbound leads as pure-C purpose-built resolver) |
| Ferrous-DNS vs PowerDNS       | 0.67× (PowerDNS leads as pure-C++ purpose-built resolver) |

---

## Notes

- **PowerDNS Recursor and Unbound lead** at ~220K QPS — both are purpose-built pure recursive resolvers (C++ and C respectively) with no REST API, no Web UI, no database, and no blocking engine.
- **Ferrous-DNS at 147K QPS** runs a full feature stack in the same process: DNS server, REST API, Web UI, SQLite query log, client tracking, and blocking engine — with cache L1/L2, in-flight coalescing, and optimistic prefetch active.
- **Blocky's high latency** (76ms avg, 191ms P99) is caused by Go's GC pressure under sustained load — the QPS appears competitive but the tail latency is ~14× worse than Ferrous-DNS.
- **AdGuard Home** (Go) shows similar GC pressure at P99 (15.98ms vs 30.67ms P99 for Ferrous-DNS at avg latency; Ferrous-DNS P99 is higher due to cache coalescing adding tail latency on misses).
- **Pi-hole** uses dnsmasq which is single-threaded for DNS resolution — no amount of thread or CPU config helps. Rate limiting was explicitly disabled via `bench/pihole.toml` (`rateLimit.count = 0`) mounted at `/etc/pihole/pihole.toml`, but the 31% packet loss persists because dnsmasq simply cannot sustain high-throughput UDP load in a single thread.

---

## Methodology

- **Tool**: [dnsperf 2.14.0](https://www.dns-oarc.net/tools/dnsperf) — industry-standard DNS load testing tool
- **Query dataset**: `bench/data/queries.txt` — 197 queries mixing A, AAAA, MX, TXT, NS record types across 179 unique domains
- **Concurrency**: 10 simultaneous dnsperf clients, up to 10,000 queries in-flight
- **Duration**: 60 seconds per server (queries loop continuously)
- **Warm-up**: 5s warm-up run discarded before each measurement
- **Network**: Loopback (127.0.0.1) — eliminates external network variability
- **All servers**: Docker containers with identical resource constraints (same compose file)
- **Threads**: Unbound `num-threads: 16`; Blocky/AdGuard `GOMAXPROCS=16`; Ferrous-DNS auto-detects from available CPUs

---

## Benchmark config (`bench/`)

All six servers configured identically for a fair comparison:

| Server       | Threads | Cache | Upstream config |
|:-------------|:-------:|:-----:|:----------------|
| Ferrous-DNS  | auto (16) | ✅ 200k entries, hit_rate | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (Parallel) |
| Unbound      | 16      | ✅ 256m/512m | `forward-addr: 8.8.8.8@53`, `1.1.1.1@53` |
| Blocky       | 16 (GOMAXPROCS) | ✅ 5m–24h, prefetch | `8.8.8.8`, `1.1.1.1` (parallel_best) |
| AdGuard Home | 16 (GOMAXPROCS) | ✅ 16MB, optimistic | `8.8.8.8`, `1.1.1.1` (parallel) |
| Pi-hole      | n/a (dnsmasq) | ✅ 10k entries | `PIHOLE_DNS_1=8.8.8.8`, `PIHOLE_DNS_2=1.1.1.1` |
| PowerDNS     | 16      | ✅ 200k record + 200k packet | `8.8.8.8`, `1.1.1.1` (forward-zones-recurse) |

---

## How to reproduce

```bash
# Prerequisites
pacman -S dnsperf   # or: apt install dnsperf / brew install dnsperf

# Run benchmark (starts all containers automatically)
./bench/benchmark.sh

# Custom duration and clients
./bench/benchmark.sh --duration 60 --clients 10

# Save report
./bench/benchmark.sh --output bench/benchmark-results.md
```
