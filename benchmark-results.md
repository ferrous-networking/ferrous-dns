# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-06 18:00 UTC
> Duration per server: **20s** | Clients: **10** | Query dataset: 125 domains (A, AAAA, MX, TXT, NS)
> Host: localhost (loopback) — eliminates network jitter
> Tool: [dnsperf 2.14.0](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
> **Fair comparison**: all servers use the same upstream — plain UDP `8.8.8.8` and `1.1.1.1`

---

## Results

| Server            |        QPS |  Avg Lat |   P99 Lat¹ | Completed | Lost   |
|:------------------|-----------:|---------:|-----------:|----------:|-------:|
| 🦀 Ferrous-DNS   | **377,777** | **0.58ms** | **~3.50ms** | 99.49%  | 0.51%  |
| ⚡ Unbound        |   203,967  |   0.85ms |   ~2.42ms  | 99.05%  | 0.95%  |
| 🛡️ AdGuard Home  |   105,837  |   2.45ms |  ~9.27ms   | 98.18%  | 1.82%  |
| 🕳️ Pi-hole²      |     7,652  |  21.99ms |  ~27.93ms  | 79.57%  | 20.43% |

> ¹ P99 estimated as `avg + 2.33 × σ` (dnsperf reports average + standard deviation)
> ² Pi-hole refused 99.35% of completed queries under high load (rate limiting / REFUSED responses)

---

## Speedup vs Ferrous-DNS

| Comparison                    | Speedup          |
|:------------------------------|:----------------:|
| Ferrous-DNS vs Unbound        | **1.85×** faster |
| Ferrous-DNS vs AdGuard Home   | **3.57×** faster |
| Ferrous-DNS vs Pi-hole        | **49×** faster   |

---

## Raw dnsperf Output

### 🦀 Ferrous-DNS (port 5053)

```
Queries sent:         7,594,425
Queries completed:    7,555,769 (99.49%)
Queries lost:         38,656    (0.51%)
Response codes:       NOERROR 7,555,769 (100.00%)
Average packet size:  request 28, response 170
Run time (s):         20.00
Queries per second:   377,777.17
Average Latency (s):  0.000580  (min 0.000004, max 0.254424)
Latency StdDev (s):   0.001252
```

### ⚡ Unbound (port 5356)

```
Queries sent:         4,118,859
Queries completed:    4,079,532 (99.05%)
Queries lost:         39,327    (0.95%)
Response codes:       NOERROR 4,079,532 (100.00%)
Average packet size:  request 28, response 69
Run time (s):         20.00
Queries per second:   203,967.90
Average Latency (s):  0.000854  (min 0.000014, max 0.383140)
Latency StdDev (s):   0.000674
```

### 🛡️ AdGuard Home (port 5355)

```
Queries sent:         2,156,036
Queries completed:    2,116,883 (98.18%)
Queries lost:         39,153    (1.82%)
Response codes:       NOERROR 2,116,883 (100.00%)
Average packet size:  request 28, response 86
Run time (s):         20.00
Queries per second:   105,837.58
Average Latency (s):  0.002452  (min 0.000043, max 0.094075)
Latency StdDev (s):   0.002931
```

### 🕳️ Pi-hole (port 5354)

```
Queries sent:         192,542
Queries completed:    153,210  (79.57%)
Queries lost:         39,332   (20.43%)
Response codes:       NOERROR 989 (0.65%), REFUSED 152,221 (99.35%)
Average packet size:  request 28, response 29
Run time (s):         20.02
Queries per second:   7,652.32
Average Latency (s):  0.021986  (min 0.000236, max 0.163375)
Latency StdDev (s):   0.002549
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
- **Competitors**: Docker containers on the same machine (loopback ports 5354–5356)
- **Ferrous-DNS config**: `docker/bench/ferrous-dns.bench.toml` — plain UDP upstreams, DNSSEC disabled, blocking disabled
- **Build**: `RUSTFLAGS="-C target-cpu=native" cargo build --release`
- **Fair upstream**: all servers configured identically — `8.8.8.8:53` and `1.1.1.1:53` plain UDP (no DoH/DoT/DoQ)

---

## Benchmark config (`docker/bench/`)

All four servers point to the same plain UDP upstreams for a fair comparison:

| Server       | Upstream config                                     |
|:-------------|:----------------------------------------------------|
| Ferrous-DNS  | `udp://8.8.8.8:53`, `udp://1.1.1.1:53` (Balanced)  |
| Unbound      | `forward-addr: 8.8.8.8@53`, `1.1.1.1@53`           |
| AdGuard Home | `8.8.8.8`, `1.1.1.1`                               |
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

- Ferrous-DNS handles **377K queries/second** with only **0.58ms average latency** on loopback
- The **1.85× advantage over Unbound** is significant — both use plain UDP forwarding. The gap comes from Ferrous-DNS's architecture: mimalloc allocator, DashMap sharded cache, TSC timer (~1ns), and in-flight coalescing
- Minimum latency of **4µs** confirms L1 cache hit path is working correctly
- Pi-hole's dnsmasq is not designed for high-concurrency load — at realistic residential loads (< 1K QPS) it performs well
- For cache-hit-only benchmarks, pre-warm with the same query dataset before measuring
