# Ferrous-DNS — Performance Benchmark Results

> Generated: 2026-03-07 18:33:38 UTC
> Duration per server: 60s | Clients: 10 | Queries: 187
>
> **Host:** Intel Core i9-9900KF @ 3.60GHz | 16 cores / 46 GB RAM | Arch Linux | Kernel 6.12.75-1-lts
>
> **Docker config (identical for all servers):**
>
> | Setting | Value |
> |:--------|:------|
> | CPUs | `cpuset: 0-15` — 16 cores |
> | Network | host mode |
> | Log level | info |
> | Cache | enabled |
> | Rate limiting | disabled |
> | Upstreams | plain UDP `8.8.8.8` / `1.1.1.1` |
> | Blocking | disabled — isolates raw forwarding performance |

## Results

| Server             |    QPS     | Avg Lat    |  P99 Lat   | Completed   | Lost       |
|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|
| 🦀 Ferrous-DNS   | 477744.311259 |     1.25ms |    36.01ms |        99.60% |       0.40% |
| 🕳️  Pi-hole   | 3814.001376 |    35.82ms |   349.64ms |        65.87% |      34.13% |
| 🛡️  AdGuard Home | 100971.452472 |     3.74ms |    14.85ms |        98.12% |       1.88% |
| ⚡ Unbound        | 1102095.339060 |     1.00ms |     2.62ms |        99.84% |       0.16% |
| 🔷 Blocky        | 102299.623904 |    78.44ms |   197.75ms |        99.62% |       0.38% |
| ⚡ PowerDNS (C++) | 899679.871217 |     2.07ms |    14.64ms |        99.82% |       0.18% |

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
