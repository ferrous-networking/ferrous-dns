# ferrous-dns — Performance Benchmark Results

> Generated: 2026-07-31 17:45:27 UTC
> Profile: `quick` — 3 runs × 10s per server, 10 dnsperf clients

This report is generated end to end by `bench/benchmark.sh`. Every number below comes from raw dnsperf output kept in `bench/results/`; nothing is transcribed by hand.

## Scenarios

| | Cache | Blocking | Query log | Servers | What it measures |
|:--|:--|:--|:--|:--|:--|
| **A** | on | off | off | all six | Theoretical ceiling |
| **B** | on | on (1M rules) | off | ferrous-dns, Blocky, AdGuard | Cost of the blocking engine |
| **C** | on | on (1M rules) | on | ferrous-dns, Blocky, AdGuard | What a user actually runs |

Unbound and PowerDNS Recursor appear only in scenario A: they have no blocking engine, so running them in B and C would compare different things. Pi-hole appears only in scenario A because loading a million rules into it means driving a gravity import, which is slow and brittle enough that it would become the thing under test.

### Scenario A — Cache only

*cache on, blocking off, query log off*. The theoretical ceiling: pure forwarding out of a warm cache.

| Server | Median QPS | QPS spread across runs | QPS p5–p95 within runs | Median avg lat | Loss |
|:-------|-----------:|:-----------------------|:-----------------------|:--------------:|-----:|
| **🦀 ferrous-dns** | 847,711 | 841,742 – 931,400 | 837,976 – 941,875 | 1.02ms | 0.00% |
| ⚡ Unbound (C) | 592,083 | 583,062 – 788,116 | 580,700 – 796,513 | 1.00ms | 0.01% |
| ⚡ PowerDNS (C++) | 388,147 | 328,582 – 416,177 | 322,068 – 502,987 | 2.38ms | 0.00% |
| 🛡️ AdGuard Home | 118,312 | 112,482 – 119,342 | 78,034 – 130,484 | 2.08ms | 0.14% |
| 🔷 Blocky (Go) | 85,443 | 85,244 – 86,666 | 84,159 – 88,280 | 2.40ms | 0.19% |
| 🕳️ Pi-hole | 19,530 | 14,001 – 26,632 | 0 – 44,133 | 6.22ms | 0.85% |

### Scenario B — Blocking

*cache on, blocking on (1M rules), query log off*. What the blocking engine costs on top of scenario A.

| Server | Median QPS | QPS spread across runs | QPS p5–p95 within runs | Median avg lat | Loss |
|:-------|-----------:|:-----------------------|:-----------------------|:--------------:|-----:|
| **🦀 ferrous-dns** | 834,485 | 758,298 – 835,344 | 741,570 – 843,751 | 0.98ms | 0.00% |
| 🛡️ AdGuard Home | 111,238 | 108,034 – 115,277 | 69,489 – 129,068 | 2.26ms | 0.14% |
| 🔷 Blocky (Go) | 97,947 | 97,801 – 98,256 | 95,423 – 99,816 | 2.16ms | 0.16% |

### Scenario C — Full stack

*cache on, blocking on (1M rules), query log on*. What a user actually runs.

| Server | Median QPS | QPS spread across runs | QPS p5–p95 within runs | Median avg lat | Loss |
|:-------|-----------:|:-----------------------|:-----------------------|:--------------:|-----:|
| **🦀 ferrous-dns** | 262,298 | 259,843 – 263,859 | 252,143 – 267,779 | 3.74ms | 0.00% |
| 🛡️ AdGuard Home | 102,497 | 70,774 – 107,752 | 68,018 – 124,435 | 2.61ms | 0.16% |
| 🔷 Blocky (Go) | 98,027 | 97,850 – 98,674 | 96,487 – 99,960 | 2.14ms | 0.16% |

> **Query log dropped entries during this scenario:** 144447 "channel full" warnings. The query-log producer uses a non-blocking `try_send` on a bounded channel and returns `Ok` when it overflows, so rows are lost silently under saturation. The QPS figure above is therefore the cost of *logging what fit*, not of logging everything.

### What each feature costs

| Scenario | ferrous-dns median QPS | vs. scenario A |
|:--|--:|--:|
| A | 847,711 | — |
| B | 834,485 | -1.6% |
| C | 262,298 | -69.1% |

## What the blocking engine actually matches

Scenario B is only meaningful if the rules it loads are reachable. Before each measurement the harness probes one name per rule syntax and compares the answer against a control name in the same zone that has no rule at all, so the result holds regardless of how a server signals a block.

| Rule syntax | Probe | Reaches the engine | Response |
|:------------|:------|:------------------:|:---------|
| exact hosts rule | `blocked-exact.canary.example` | ✅ yes | `NOERROR|0.0.0.0` |
| wildcard suffix rule | `sub.blocked-wildcard.canary.example` | ❌ **no** | `NOERROR|192.0.2.1` |
| adblock rule, apex | `blocked-adblock.canary.example` | ✅ yes | `NOERROR|0.0.0.0` |
| adblock rule, subdomain | `sub.blocked-adblock.canary.example` | ❌ **no** | `NOERROR|192.0.2.1` |
| Aho-Corasick substring rule | `x-blocked-ac-canary-y.canary.example` | ❌ **no** | `NOERROR|192.0.2.1` |
| _(control, no rule)_ | `not-blocked.canary.example` | — | `NOERROR|192.0.2.1` |

> **Not every rule syntax reaches the matcher.** `BlockIndex::is_blocked` consults the bloom filter before the suffix trie and the Aho-Corasick automaton, but the compiler only calls `bloom.set()` for exact entries — wildcard and pattern rules are added to their structures and then gated behind a filter that was never told about them. Adblock-syntax rules (`||domain^`) parse as exact entries, so they match the apex and not its subdomains.
>
> Scenario B is therefore an honest measurement of the **exact-match path at 1M rules**, which is what the overwhelming majority of real blocklist entries are, and not of the wildcard or substring matchers.

## Workload

The dataset is generated, not checked in — `bench/generate-queries.py` and `bench/generate-blocklist.py` are deterministic given `--seed`, so these files reproduce byte for byte.

| | |
|---|---|
| Recurring working set | 150,000 domains, Zipf α = 0.9 |
| Cold-tail (churn) | 200,000 single-occurrence domains (10.0% of the stream) |
| Reverse names | 60,000 (public IPv4 space only) |
| **Unique names total** | **410,000** |
| Query lines | 2,000,000, looped for the run duration |
| Record type mix | A 69.933%, AAAA 15.02%, MX 5.022%, NS 3.033%, PTR 3.0%, TXT 3.991% |
| Block rate of the stream | 24.198% |
| Blocklist rules | 950,000 exact + 40,000 wildcard + 9,996 pattern |

The working set is deliberately larger than the 100k L1 block-decision cache. Below that threshold every decision is memoised after warm-up and the benchmark measures a hash lookup instead of the DNS pipeline — which is what the previous 187-domain dataset did.

Two caveats worth stating plainly:

- dnsperf loops the datafile, so the cold-tail pool is only genuinely cold within a single pass. Sustained pressure on the decision cache comes from the working set exceeding its capacity, not from churn alone.
- Servers that answer faster consume more of the stream in the same wall time and therefore touch more unique names. That works against the fastest server in the table, not for it.

## Build provenance

| | |
|---|---|
| ferrous-dns version | `ferrous-dns 0.1.0` |
| Git commit | `962dec75c2de567c91671f0ddf14edd33ab64a36` (dirty worktree) |
| Build flags | `RUSTFLAGS="-C target-cpu=native (the documented build line; RUSTFLAGS was not set in the shell that ran the benchmark, so this is the intended value, not an observed one)"` |
| Binary origin | locally built target/release/ferrous-dns, copied into the bench image |

> **This is not the binary you download.** These numbers come from a build with `-C target-cpu=native`, which lets the compiler use every instruction set extension the benchmark host has. The published Docker image is built generically so it runs on any x86-64 machine, and will measure lower on the same hardware. Reproducing the tables above requires the build line in *How to reproduce*, not the released image.

## Test machine

| | |
|---|---|
| CPU | Intel(R) Core(TM) i9-9900KF CPU @ 3.60GHz |
| Threads | 16 |
| Kernel | 6.18.39-1-lts |
| Server cpuset | `0-7` |
| Load generator cpuset | `8-15` |

The harness splits the host cores in half: every server under test runs pinned to the lower half with an identical CPU quota, and dnsperf runs pinned to the upper half so the load generator never steals CPU from the server it is measuring. Servers are started, measured and stopped one at a time, so an idle competitor never contends for cores.

One asymmetry to disclose: ferrous-dns pins its Tokio workers to individual cores within the cpuset, while the other servers let their runtimes schedule freely inside the same cpuset.

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC, JSON output (`-j`), per-second sampling (`-S 1`)
- **Runs**: 3 per server per scenario. Tables report the **median** across runs plus the full min–max spread
- **Percentiles**: p5/p95 are computed over the per-second throughput samples *within* runs. Percentiles across a handful of runs would be noise presented as precision, so they are not reported
- **Loss**: reported for every server in every scenario. Throughput without a loss rate is half a metric
- **Warm-up**: 20s against the full dataset before the first measured run. A short warm-up leaves most of a working set this size missing, which turns the measurement into a test of the upstream path
- **In-flight cap**: `-q 1000` per client
- **Fairness**: every server forwards to the same local stub upstream, loads the identical hosts-format blocklist in scenarios B and C, has its cache sized to hold the working set, and runs with rate limiting off and thread counts matched to the cpuset

**Scope.** This is a cache-hit forwarding benchmark, not a recursion benchmark. Every server runs with its cache enabled and its upstreams pointed at a local stub, so Unbound and PowerDNS Recursor operate in forward mode rather than recursing from the root — not the workload they are built around. The numbers describe how fast each server answers from its own cache, which is what a home or LAN resolver spends most of its time doing. They say nothing about recursive resolution performance.

**Why a stub upstream.** A working set this size is larger than any of these caches, so there is a permanent stream of misses. Sending it to a public resolver measures the round-trip time to that resolver rather than the server under test — an earlier version of this harness did exactly that and recorded ferrous-dns at 5,498 q/s with 120 ms average latency. The stub answers any name at any depth instantly over loopback, identically for every server.

## How to reproduce

```bash
# Install prerequisites
pacman -S dnsperf bind    # Arch    (dig comes from bind)
apt install dnsperf dnsutils   # Debian/Ubuntu

# Build the release binary — the bench image copies it in
RUSTFLAGS="-C target-cpu=native" cargo build --release -p ferrous-dns
docker compose -f bench/docker-compose.yml build ferrous-dns

# One scenario, quick profile (~5 minutes)
./bench/benchmark.sh --scenario A

# All three scenarios at publication settings
./bench/benchmark.sh --scenario all --profile publish

# Regenerate the workload from scratch
./bench/benchmark.sh --scenario all --profile publish --regen
```

Raw per-run dnsperf output is written to `bench/results/`. See `bench/README.md` for what each knob does.
