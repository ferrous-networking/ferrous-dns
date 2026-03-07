# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-07 14:57:11 UTC
> Duration per server: 60s | Clients: 10 | Queries: 187

## Results

| Server             |    QPS     | Avg Lat    |  P99 Lat   | Completed   | Lost       |
|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|
| 🦀 Ferrous-DNS   | 155889.810443 |     2.16ms |     7.72ms |        98.78% |       1.22% |
| 🕳️  Pi-hole   | 4001.353552 |    40.88ms |   515.46ms |        67.02% |      32.98% |
| 🛡️  AdGuard Home | 106400.363913 |     3.24ms |    13.44ms |        98.20% |       1.80% |
| ⚡ Unbound        | 1120135.813310 |     0.98ms |     2.67ms |        99.85% |       0.15% |
| 🔷 Blocky        | 102681.874028 |    82.69ms |   204.59ms |        99.71% |       0.29% |
| ⚡ PowerDNS (C++) | 856978.055278 |     2.08ms |     7.74ms |        99.82% |       0.18% |

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
- **Query dataset**: `scripts/bench-data/queries.txt` (mix of A, AAAA, MX, TXT, NS)
- **Workload**: All servers use the same query dataset in loop mode
- **Warm-up**: 5s warm-up before each measurement
- **P99**: Estimated from average + 2.33×σ (dnsperf provides average + stddev)

## How to reproduce

```bash
# Install dnsperf
apt install dnsperf   # Debian/Ubuntu
brew install dnsperf  # macOS

# Run benchmark
./scripts/benchmark-competitors.sh --duration 30 --clients 10

# With custom Ferrous-DNS address
FERROUS_DNS_ADDR=192.168.1.10:53 ./scripts/benchmark-competitors.sh
```
