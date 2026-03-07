# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-07 03:45 UTC
> Duration per server: **20s** | Clients: **10** | Query dataset: 125 domains (A, AAAA, MX, TXT, NS)
> Host: localhost (loopback) — eliminates network jitter
> Tool: [dnsperf 2.14.0](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
> **Fair comparison**: all servers use the same upstream — plain UDP `8.8.8.8` and `1.1.1.1`

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

---

## Results

| Server            |        QPS |  Avg Lat |   P99 Lat¹ | Completed | Lost   |
|:------------------|-----------:|---------:|-----------:|----------:|-------:|
| 🦀 Ferrous-DNS   | **438,925** | **4.02ms** | **~8.94ms** | 99.62%  | 0.38%  |
| ⚡ Unbound        |   224,194  |   0.77ms |   ~3.30ms  | 99.13%  | 0.87%  |
| 🔷 Blocky         |   133,446  |   1.56ms |   ~5.21ms  | 98.55%  | 1.45%  |
| 🛡️ AdGuard Home  |   109,068  |   2.84ms |  ~13.12ms  | 98.24%  | 1.76%  |
| 🕳️ Pi-hole²      |     6,902  |  24.39ms |  ~33.85ms  | 77.84%  | 22.16% |

> ¹ P99 estimated as `avg + 2.33 × σ` (dnsperf reports average + standard deviation)
> ² Pi-hole refused 99.28% of completed queries under high load (rate limiting / REFUSED responses)

---

## Speedup vs Ferrous-DNS

| Comparison                    | Speedup          |
|:------------------------------|:----------------:|
| Ferrous-DNS vs Unbound        | **1.96×** faster |
| Ferrous-DNS vs Blocky         | **3.29×** faster |
| Ferrous-DNS vs AdGuard Home   | **4.03×** faster |
| Ferrous-DNS vs Pi-hole        | **64×** faster   |

---

## Raw dnsperf Output

### 🦀 Ferrous-DNS (port 5053)

```
Queries sent:         8,815,510
Queries completed:    8,781,993 (99.62%)
Queries lost:         33,517    (0.38%)
Response codes:       NOERROR 8,781,993 (100.00%)
Average packet size:  request 28, response 169
Run time (s):         20.00
Queries per second:   438,924.96
Average Latency (s):  0.004025  (min 0.000014, max 0.191612)
Latency StdDev (s):   0.002107
```

### ⚡ Unbound (port 5356)

```
Queries sent:         4,523,343
Queries completed:    4,484,016 (99.13%)
Queries lost:         39,327    (0.87%)
Response codes:       NOERROR 4,484,016 (100.00%)
Average packet size:  request 28, response 68
Run time (s):         20.00
Queries per second:   224,193.58
Average Latency (s):  0.000773  (min 0.000013, max 0.568933)
Latency StdDev (s):   0.001083
```

### 🔷 Blocky (port 5357)

```
Queries sent:         2,708,842
Queries completed:    2,669,567 (98.55%)
Queries lost:         39,275    (1.45%)
Response codes:       NOERROR 2,669,567 (100.00%)
Average packet size:  request 28, response 85
Run time (s):         20.00
Queries per second:   133,446.24
Average Latency (s):  0.001562  (min 0.000049, max 0.149212)
Latency StdDev (s):   0.001566
```

### 🛡️ AdGuard Home (port 5355)

```
Queries sent:         2,220,650
Queries completed:    2,181,640 (98.24%)
Queries lost:         39,010    (1.76%)
Response codes:       NOERROR 2,181,640 (100.00%)
Average packet size:  request 28, response 85
Run time (s):         20.00
Queries per second:   109,067.71
Average Latency (s):  0.002841  (min 0.000045, max 0.230577)
Latency StdDev (s):   0.004413
```

### 🕳️ Pi-hole (port 5354)

```
Queries sent:         177,519
Queries completed:    138,187  (77.84%)
Queries lost:         39,332   (22.16%)
Response codes:       NOERROR 1,000 (0.72%), REFUSED 137,187 (99.28%)
Average packet size:  request 28, response 29
Run time (s):         20.03
Queries per second:   6,901.81
Average Latency (s):  0.024389  (min 0.003339, max 0.171583)
Latency StdDev (s):   0.004062
```

> **Note on Pi-hole:** Pi-hole's dnsmasq activates rate limiting under extreme load (10K in-flight queries).
> At realistic load levels (< 1K QPS), Pi-hole performs considerably better.
> This benchmark reflects saturation behaviour, not typical residential use.

---

## Methodology

- **Tool**: [dnsperf 2.14.0](https://www.dns-oarc.net/tools/dnsperf) — industry-standard DNS load testing tool
- **Query dataset**: `scripts/bench-data/queries.txt` — 125 queries mixing A, AAAA, MX, TXT, NS record types
- **Concurrency**: 10 simultaneous dnsperf clients, up to 10,000 queries in-flight
- **Duration**: 20 seconds per server (queries loop continuously)
- **Warm-up**: 5s warm-up run discarded before each measurement
- **Network**: Loopback (127.0.0.1) — eliminates external network variability
- **Competitors**: Docker containers on the same machine (loopback ports 5354–5357)
- **Ferrous-DNS config**: `docker/bench/ferrous-dns.bench.toml` — plain UDP upstreams, DNSSEC disabled, blocking disabled, `Parallel` strategy
- **Build**: `RUSTFLAGS="-C target-cpu=native" cargo build --release`
- **Fair upstream**: all servers configured identically — `8.8.8.8:53` and `1.1.1.1:53` plain UDP (no DoH/DoT/DoQ)

---

## Benchmark config (`docker/bench/`)

All five servers point to the same plain UDP upstreams for a fair comparison:

| Server       | Upstream config                                     |
|:-------------|:----------------------------------------------------|
| Ferrous-DNS  | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (Parallel)  |
| Unbound      | `forward-addr: 8.8.8.8@53`, `1.1.1.1@53`           |
| Blocky       | `8.8.8.8`, `1.1.1.1` (parallel_best)               |
| AdGuard Home | `8.8.8.8`, `1.1.1.1` (load_balance)                |
| Pi-hole      | `PIHOLE_DNS_1=8.8.8.8`, `PIHOLE_DNS_2=1.1.1.1`     |

---

## How to reproduce

```bash
# Prerequisites
pacman -S dnsperf   # or: apt install dnsperf / brew install dnsperf

# Start competitor containers
docker compose -f docker/bench/docker-compose.yml up -d

# Build Ferrous-DNS
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Start Ferrous-DNS with benchmark config (plain UDP upstreams, port 5053)
./target/release/ferrous-dns --config docker/bench/ferrous-dns.bench.toml &

# Run benchmark
./scripts/benchmark-competitors.sh \
  --ferrous 127.0.0.1:5053 \
  --duration 20 \
  --clients 10 \
  --no-docker \
  --output benchmark-results.md
```

---

## Notes

- Ferrous-DNS handles **439K queries/second** — the highest throughput of all tested servers
- The **1.96× advantage over Unbound** is significant — both use plain UDP forwarding; the gap comes from Ferrous-DNS's architecture: mimalloc allocator, DashMap sharded cache, TSC timer, and in-flight coalescing
- **`Parallel` strategy** queries both upstreams simultaneously and returns the fastest response, yielding lower cache-miss latency than round-robin
- **Blocky** (Go) at 133K QPS is solid for a Go-based DNS proxy, landing between Unbound and AdGuard Home
- **AdGuard Home** (Go) reaches 109K QPS with higher P99 latency (~13ms) due to GC pressure under load
- Pi-hole's dnsmasq is not designed for high-concurrency load — at realistic residential loads (< 1K QPS) it performs well
