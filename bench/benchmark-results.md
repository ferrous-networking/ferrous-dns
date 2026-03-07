# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-07 16:45:10 UTC
> Duration per server: 60s | Clients: 10 | Queries: 187

## Results

| Server             |    QPS     | Avg Lat    |  P99 Lat   | Completed   | Lost       |
|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|
| 🦀 Ferrous-DNS   | 427310.634759 |     1.61ms |    23.31ms |        99.56% |       0.44% |
| 🕳️  Pi-hole   | 3948.207078 |    43.55ms |   534.72ms |        66.74% |      33.26% |
| 🛡️  AdGuard Home | 102031.612700 |     3.67ms |    14.43ms |        98.14% |       1.86% |
| ⚡ Unbound        | 1097093.328503 |     0.99ms |     2.48ms |        99.84% |       0.16% |
| 🔷 Blocky        | 103661.855863 |    82.53ms |   203.68ms |        99.73% |       0.27% |
| ⚡ PowerDNS (C++) | 916707.445673 |     1.94ms |     7.33ms |        99.83% |       0.17% |

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
