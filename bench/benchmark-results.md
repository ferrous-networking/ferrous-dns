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

| Server            |        QPS |  Avg Lat |   P99 Lat¹ | Completed | Lost   |
|:------------------|-----------:|---------:|-----------:|----------:|-------:|
| ⚡ Unbound (C)    |   242,646  |   1.72ms |    6.53ms  |  99.20%  | 0.80%  |
| 🦀 Ferrous-DNS   | **147,184** | **2.00ms** | **14.32ms** | 98.69%  | 1.31%  |
| 🛡️ AdGuard Home  |    97,848  |   3.88ms |   15.56ms  |  98.05%  | 1.95%  |
| 🔷 Blocky (Go)    |    93,860  |  70.09ms |  175.61ms  |  99.26%  | 0.74%  |
| 🕳️ Pi-hole²      |     4,902  |  30.07ms |  257.01ms  |  71.28%  | 28.72% |

> ¹ P99 estimated as `avg + 2.33 × σ` (dnsperf reports average + standard deviation)
> ² Pi-hole lost 29% of packets under sustained load — dnsmasq is fundamentally single-threaded; `bench/pihole.toml` mounts `rateLimit.count = 0` but the bottleneck is architectural

---

## Speedup vs Competitors

| Comparison                    | Result           |
|:------------------------------|:----------------:|
| Ferrous-DNS vs AdGuard Home   | **1.50× faster** |
| Ferrous-DNS vs Blocky         | **1.57× faster** |
| Ferrous-DNS vs Pi-hole        | **30.0× faster** |
| Ferrous-DNS vs Unbound        | 0.61× (Unbound leads as pure-C purpose-built resolver) |

---

## Notes

- **Unbound leads** at 242K QPS — it is a pure-C recursive resolver with no REST API, no Web UI, no database, and no blocking engine. It is purpose-built for one task.
- **Ferrous-DNS at 147K QPS** runs a full feature stack in the same process: DNS server, REST API, Web UI, SQLite query log, client tracking, and blocking engine — with cache L1/L2, in-flight coalescing, and optimistic prefetch active.
- **Blocky's high latency** (70ms avg, 175ms P99) is caused by Go's GC pressure under sustained load — the QPS appears competitive but the tail latency is ~12× worse than Ferrous-DNS.
- **AdGuard Home** (Go) also shows GC pressure at P99 (15.56ms vs 14.32ms for Ferrous-DNS).
- **Pi-hole** uses dnsmasq which is single-threaded for DNS resolution — no amount of thread or CPU config helps. Rate limiting was explicitly disabled via `bench/pihole.toml` (`rateLimit.count = 0`) mounted at `/etc/pihole/pihole.toml`, but the 29% packet loss persists because dnsmasq simply cannot sustain high-throughput UDP load in a single thread.

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

All five servers configured identically for a fair comparison:

| Server       | Threads | Cache | Upstream config |
|:-------------|:-------:|:-----:|:----------------|
| Ferrous-DNS  | auto (16) | ✅ 200k entries, hit_rate | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (Parallel) |
| Unbound      | 16      | ✅ 256m/512m | `forward-addr: 8.8.8.8@53`, `1.1.1.1@53` |
| Blocky       | 16 (GOMAXPROCS) | ✅ 5m–24h, prefetch | `8.8.8.8`, `1.1.1.1` (parallel_best) |
| AdGuard Home | 16 (GOMAXPROCS) | ✅ 16MB, optimistic | `8.8.8.8`, `1.1.1.1` (parallel) |
| Pi-hole      | n/a (dnsmasq) | ✅ 10k entries | `PIHOLE_DNS_1=8.8.8.8`, `PIHOLE_DNS_2=1.1.1.1` |

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
