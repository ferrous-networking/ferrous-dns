# Benchmark harness

Measures ferrous-dns against Pi-hole, AdGuard Home, Unbound, Blocky and PowerDNS
Recursor across three scenarios, and writes `benchmark-results.md`.

```bash
# Build the binary the bench image copies in
RUSTFLAGS="-C target-cpu=native" cargo build --release -p ferrous-dns
docker compose -f bench/docker-compose.yml build ferrous-dns

# One scenario (~6 min)
./bench/benchmark.sh --scenario A

# Everything, at publication settings
./bench/benchmark.sh --scenario all --profile publish
```

## Scenarios

| | Cache | Blocking | Query log | Servers |
|:--|:--|:--|:--|:--|
| **A** | on | off | off | all six |
| **B** | on | on (1M rules) | off | ferrous-dns, Blocky, AdGuard Home |
| **C** | on | on (1M rules) | on | ferrous-dns, Blocky, AdGuard Home |

Unbound and PowerDNS Recursor are absent from B and C because they have no
blocking engine. Pi-hole is absent because loading a million rules into it means
driving a gravity import, which is slow and brittle enough that it would become
the thing under test rather than a participant in it.

## Profiles

| Profile | Duration | Runs | Warm-up | Scenario A | All three |
|:--|--:|--:|--:|--:|--:|
| `quick` (default) | 10s | 3 | 20s | ~6 min | ~25 min |
| `publish` | 30s | 5 | 45s | ~17 min | ~50 min |

Scenarios B and C take longer per server than A even though they run half as
many: ferrous-dns, Blocky and AdGuard each compile a 1M-rule blocklist at
startup, and ferrous-dns is restarted once so the compile happens at boot.

Any of `--duration`, `--runs`, `--warmup` and `--clients` overrides the profile.

## The workload is generated, not checked in

A 45 MB query file and a 30 MB blocklist do not belong in git. Both generators
are deterministic given `--seed`, so the same files can be rebuilt at any time:

```bash
python3 bench/generate-queries.py --out bench/data/queries-realistic.txt
python3 bench/generate-blocklist.py
```

`benchmark.sh` runs both automatically when the files are missing, or on
`--regen`.

### `generate-queries.py`

| Flag | Default | |
|:--|--:|:--|
| `--unique` | 150000 | recurring working set, sampled Zipf |
| `--zipf` | 0.9 | Zipf α |
| `--lines` | 2000000 | query lines emitted |
| `--churn` | 10 | % of the stream drawn from a single-occurrence cold-tail pool |
| `--block-rate` | 25 | % of the stream that should hit a blocked domain |
| `--seed` | 42 | |

The record mix is ~70% A, 15% AAAA, 5% MX, 4% TXT, 3% NS, 3% PTR. The head of
the Zipf distribution is seeded with real domains so the hot end of the stream
looks like actual traffic; the rest is synthesised.

Writes the dnsperf datafile, a `.manifest.json` recording every parameter *and
the realised statistics*, and `blocked-domains.txt` — which
`generate-blocklist.py` consumes, so the query set and the blocklist cannot
drift apart.

Two things it deliberately does:

- **The working set exceeds the block decision cache.** That cache is a 256-entry
  thread-local L0 in front of a 100k L1 of 64 LRU shards with a 60s TTL. Below 100k
  unique names every decision is memoised after warm-up and the benchmark
  measures a hash lookup rather than the blocking engine — which is exactly what
  the previous 187-domain dataset did.
- **PTR names come from public IPv4 space only.** ferrous-dns has
  `block_private_ptr` on by default, so reverse lookups for RFC 1918 addresses
  would be counted as blocks and quietly contaminate scenario A.

### `generate-blocklist.py`

Produces two files:

- `blocklist.txt` — ~95% of the rules, **hosts format**. This is the only syntax
  ferrous-dns, Blocky and AdGuard Home all parse identically, so it is the file
  every server loads. Fairness depends on all three seeing the same rules.
- `blocklist-advanced.txt` — wildcard (`*.domain`) and substring (`/pattern/`)
  rules, plus the canaries. Loaded by ferrous-dns only: mixing these syntaxes
  into the hosts file breaks AdGuard's format detection.

## Why there is a stub upstream

`stub-upstream.conf` runs an unbound instance on `127.0.0.1:5300` configured with
`local-zone: "." redirect`, which answers any name at any depth instantly. Every
server under test forwards there instead of to `8.8.8.8` / `1.1.1.1`.

This is not a detail. A realistic working set is larger than these servers'
caches, so there is a permanent stream of cache misses. Sending that stream to
public resolvers makes the benchmark measure the round-trip time to Google: the
first version of this harness recorded ferrous-dns at **5,498 QPS with 120 ms
average latency**, which is a property of the network, not of the software. With
the stub the same configuration measures ~920,000 QPS.

The stub is pinned to the load-generator core set rather than the server's:
taking cycles from dnsperf understates every server equally, taking them from the
server under test would not.

## The canary probes

Before every measurement with blocking on, the harness queries one name per rule
syntax and compares each answer against a control name in the same zone that has
no rule at all. Comparing against a control works regardless of whether a server
signals a block with `0.0.0.0`, NXDOMAIN or REFUSED.

This exists because scenario B is only meaningful if the rules it loads are
reachable. As of this writing ferrous-dns matches **2 of the 5** syntaxes probed:
exact rules and the apex of an `||domain^` rule. Wildcard rules, `||domain^`
subdomains and substring rules are not matched — `BlockIndex::is_blocked`
consults the bloom filter before the suffix trie and the Aho-Corasick automaton,
but the compiler only calls `bloom.set()` for exact entries. The result is
recorded in the report rather than asserted, so the published table always states
the engine's real behaviour.

## Output

| Path | |
|:--|:--|
| `benchmark-results.md` | the report; tracked in git |
| `results/scenario-<A\|B\|C>.json` | aggregated numbers per scenario |
| `.run/raw/` | raw dnsperf NDJSON, one file per run |
| `.run/ferrous-<scenario>.toml` | the exact config each scenario ran with |
| `.run/provenance.json` | git SHA, version, RUSTFLAGS, CPU, cpusets |

`benchmark.sh` computes no statistics itself; it keeps raw dnsperf output and
`aggregate-results.py` does the arithmetic. The previous harness formatted each
row into a markdown string the moment it was measured, which discarded the
numbers and made a median across runs impossible to compute after the fact.

Two kinds of spread are reported because they answer different questions: median
and min–max **across runs** for run-to-run variance, and p5/p95 of the per-second
samples **within** runs for throughput stability. Percentiles across three or
five runs would be noise presented as precision, so they are not reported.

## Files

| | |
|:--|:--|
| `benchmark.sh` | orchestration: containers, scenarios, dnsperf |
| `aggregate-results.py` | statistics and report generation |
| `generate-queries.py`, `generate-blocklist.py` | workload generators |
| `docker-compose.yml` | all servers, the stub upstream, the blocklist HTTP server |
| `Dockerfile.ferrous` | thin image over a host-built `target/release/ferrous-dns` |
| `ferrous-dns-config.toml` | base config; `benchmark.sh` renders per-scenario copies |
| `blocky-config.yml`, `blocky-config-blocking.yml` | Blocky, blocking off and on |
| `adguard-templates/` | AdGuard config, copied into scratch before each start |
| `unbound.conf`, `powerdns-recursor.yml`, `pihole.toml` | remaining competitors |
| `stub-upstream.conf` | the local catch-all upstream |
| `blocklist-nginx.conf` | serves the blocklist fixtures over HTTP |

## Gotchas

- **`bench/ferrous-dns-config.toml` disables authentication.** The blocklist
  tables have no CLI import path and the REST route sits behind `require_auth`,
  so the harness needs unauthenticated access to register blocklist sources. This
  config is bench-only; never copy that section into a deployment.
- **AdGuard rewrites its config in place** and re-chowns it to `root:0600`. The
  tracked templates are copied into `.run/adguard-conf` before each start rather
  than mounted, which is why `adguard-config/` no longer exists.
- **PowerDNS Recursor refuses loopback forwarders** unless `outgoing.dont_query`
  is cleared. It also caches SERVFAIL, so if the stub upstream is not up before
  PowerDNS starts, it will keep failing after the stub arrives.
- **Port 5355 is LLMNR**, held by systemd-resolved on many hosts. AdGuard is on
  5359 for that reason.
- **`docker compose` state is torn down on exit**, including on Ctrl-C.
