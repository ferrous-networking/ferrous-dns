# Internals

[Benchmarks](benchmarks.md) shows the numbers. This page documents the machinery that produces them: how packets get in and out of the kernel, what is cached where, and which of it you can actually tune.

---

## Listeners and runtime workers

Ferrous DNS creates one UDP socket and TCP listener per Tokio worker, all bound to the same address with `SO_REUSEPORT`. The kernel hashes incoming datagrams across sockets, avoiding a shared receive queue.

Sockets use `SO_REUSEADDR` and 4 MB send/receive buffers to absorb bursts. Runtime and blocking-pool threads are not pinned to individual CPUs; the OS schedules them within the process's cpuset. Busy polling and per-socket CPU hints are not enabled.

The worker count defaults to Tokio's available parallelism. Set `TOKIO_WORKER_THREADS` to a positive integer to override it; DNS listener count follows the actual runtime count. There is no `workers` TOML key. Use container CPU limits or `taskset` when process-level placement is required.

TCP DNS and DoT listeners write each answer's length prefix and payload in one vectored write, so an answer leaves as one TCP segment or one TLS record. Written separately, the payload waited behind Nagle's algorithm for the client's delayed ACK of the 2-byte prefix, stalling even cached answers by tens of milliseconds at low query rates. The listeners also enable `TCP_NODELAY`, so an answer to a pipelined query does not wait for the ACK of the one before it. This does not change UDP processing or require a configuration option.

---

## Upstream connection reuse

Upstream TCP and DoT queries are framed the same way, with the length prefix and query in one vectored write, and the sockets enable `TCP_NODELAY` so a query on a reused connection does not wait for the ACK of the previous exchange. DoT enables it before the TLS handshake, which also sends the handshake flights without delay; certificate verification and query deadlines are unchanged.

Each DoH transport retains its HTTP client instead of discarding healthy connection pools at a fixed age. Transports are keyed by the endpoint and its resolved addresses, so an upstream address change gets its own client rather than reusing the previous destination. HTTP pool idle expiry and server-initiated connection closure still apply.

---

## Batched syscalls: recvmmsg / sendmmsg

On Linux the UDP path reads and writes datagrams in batches of **64** using `recvmmsg` and `sendmmsg`, amortizing the syscall over up to 64 queries. Receive buffers and control-message storage are allocated once per worker and reused.

Receives are nonblocking: a single available query is processed immediately, without waiting to fill the batch. Sparse-query latency should be measured with idle gaps between requests, not inferred from a saturated throughput benchmark.

This is selected at compile time (`#[cfg(target_os = "linux")]`), not by a feature flag or config key. On non-Linux targets the server falls back to a single-datagram loop with the same behaviour and lower throughput. Every target needs dual-stack `AF_INET6` sockets (IPv4 is handled as v4-mapped addresses); platforms without them, such as kernels built without IPv6, are not supported.

Workers yield at batch boundaries after processing 256 datagrams, so a continuously readable socket cannot monopolize a Tokio worker. The non-Linux loop uses the same packet budget.

---

## Correct source address on multi-homed hosts (IPV6_PKTINFO)

A server bound to a wildcard address on a machine with several addresses can answer from the *wrong* source IP, and clients will drop such replies. Ferrous DNS enables `IPV6_RECVPKTINFO` on its UDP sockets, records the destination address of each incoming query from the control message, and writes it back as a control message on the reply — so the answer always leaves from the address the client sent to.

The DNS sockets are dual-stack `AF_INET6`: an IPv4 `bind_address` is bound in v4-mapped form (`::ffff:a.b.c.d`) and IPv4 clients arrive the same way, so a single `IPV6_PKTINFO` path covers both families. Client addresses are normalised back to plain IPv4 before they reach logging, grouping, and blocking.

---

## The cache is three things, not one

### L1 — thread-local hot cache

- **1024 entries per worker thread**, LRU, compile-time constant, not sized by any config key. Total footprint is 1024 × the number of worker threads.
- Holds **A/AAAA answers only** (`Arc<Vec<IpAddr>>`). CNAMEs, negative answers and wire-format records for other types live in L2 exclusively, so only A/AAAA lookups probe L1.
- Keys are built in a stack buffer, so a lookup under 260 bytes of key allocates nothing.
- Invalidated across threads through a global generation counter.

### L2 — the shared cache

This is the real DNS cache, and it is what the `[dns] cache_*` keys configure.

| Property | Value |
|:---------|:------|
| Capacity | `cache_max_entries`, default **200,000** |
| Structure | Sharded `DashMap`, `cache_shard_amount` shards (auto: 4 × cores, clamped to 8–256) |
| Eviction | `cache_eviction_strategy`: `hit_rate` (default), `lru`, `lfu`, `lfu-k` |
| Eviction style | Probabilistic — samples `cache_eviction_sample_size` candidates instead of scanning |
| Record types | **All of them** — A/AAAA as parsed IPs, CNAME, everything else as the upstream response with every record TTL clamped to `cache_min_ttl`..`cache_max_ttl`, its OPT replaced by one of ours: its DO bit records whether the answer holds DNSSEC records, and a private option (code 65001) holds the entry TTL and the offset of every record's TTL field. A hit rewrites each TTL to the record's TTL less the entry's age, capped at what the entry has left (RFC 1035 §3.2.1), with a record past its own TTL given the 2 s stale TTL (RFC 8767 §4) |
| Negative answers | Separate negative cache with its own 300 s floor, deliberately outside `cache_min_ttl` / `cache_max_ttl` |
| Miss short-circuit | A bloom filter sized at 2 × capacity (1% false positives) skips the map on definite misses |

On top of that sit **optimistic refresh** (popular entries renewed before expiry, `cache_optimistic_refresh` and friends), **stale-while-revalidate** (a stale entry is served with a 2 s TTL while the refresh is queued), and **in-flight coalescing** (N concurrent misses for the same key produce exactly one upstream query).

### L0/L1 — the block decision cache

Blocking decisions have their own two-tier cache, separate from the answer cache:

| Tier | Capacity | Eviction | Scope |
|:-----|:---------|:---------|:------|
| L0 | 256 | LRU | Thread-local |
| L1 | 100,000 across 64 shards | LRU | Shared |

Entries are keyed on `(domain, group_id)` — the same domain can be blocked for one client group and allowed for another — with a 60-second TTL. L0 is invalidated by bumping a global epoch, L1 by clearing shards, so a blocklist change takes effect without walking either structure. None of it is configurable; all values are compile-time constants.

---

## Fast path for cache hits

For a cache-hit A/AAAA query, the response is built directly from wire bytes — no full DNS message construction — and queued inline for the next `sendmmsg` batch. Queries with the DNSSEC OK (DO) bit set skip the fast path and take the regular resolution route, since they need the full record set.

A cache hit for the other types re-issues the stored response. For an EDNS client with no cookie, if the entry holds no DNSSEC records, that is a copy with the ID and flags patched. A client without OPT gets the copy minus the trailing OPT, and a client cookie swaps that OPT for one echoing it; neither walks the message. Only an entry holding RRSIG, NSEC or NSEC3 records costs a walk, to strip them for the client without DO. A hit the fast path declines (too big for the client's UDP buffer, or an extended RCODE a client without OPT cannot receive) is logged by the resolution path that answers it, not twice.

The resolver wrappers preserve borrowed domain lookups through the local-PTR and filter layers, avoiding a temporary owned `DnsQuery` allocation on each cache probe. PTR interception, local-domain rewriting, and authoritative local NODATA behavior remain on their existing paths.

UDP fallback processing has a shared limit of **4096 in-flight queries**, independent of worker count and per-client rate limits. Admission happens before packet allocation and task creation. When full, additional fallback datagrams are dropped rather than queued; clients can retry. Shedding logs a `UDP fallback capacity exhausted` warning at most once per second, with the datagrams shed since the previous warning (`shed`) and since startup (`total_shed`), so it can be told apart from packet loss. Inline cache hits remain serviceable while fallback capacity is exhausted.

## Resolution path

Everything the inline path does not answer — cache misses, blocked and refused queries, DO-bit queries, and every TCP, DoT, DoH and DoQ query including cache hits — goes through one resolution path. It decodes the query with the same wire parser as the fast path and writes the response straight to wire; hickory only decodes queries that parser declines (internationalized or escaped names, uncommon record types, several questions), so cache keys stay identical either way. Upstream queries are likewise encoded directly, with the transaction ID and client cookie drawn in one call to the OS random source.

---

## Blocklist compilation

Enabled blocklist sources are compiled into a matcher where each domain carries a `u64` bitmask of the sources that contributed it, which is what makes "why is this blocked?" answerable without re-querying every list.

Downloads are limited to four concurrent requests per build. HTTP and database operations stay asynchronous; parsing, regex compilation, and index construction run as one blocking job on the bounded build pool.

A download fails after 10 seconds without a connection, 30 seconds without receiving data, or 5 minutes in total. A large list over a slow link can therefore finish, while a server that stops sending, or trickles bytes forever, cannot hold a build indefinitely.

The engine keeps the text of every list it last downloaded, about the size of the list files in memory. A sync (the dashboard refresh action, `POST /api/blocklist-sources/{id}/sync`, or the Pi-hole gravity action) and the daily job download every list again. Any other rebuild reuses the held copies and downloads only a list it does not hold yet, such as a new source or a changed URL. A failed download keeps the held copy rather than dropping the list from the index.

Startup, periodic, and mutation-triggered rebuilds are serialized per engine. A mutation arriving during a build queues another reload so its changes cannot be lost to an older publication. Reloads queued behind the same build are coalesced: one build that starts after all of them satisfies every waiter, so a burst of mutations costs at most two rebuilds rather than one per request. A reload runs detached from the request that triggered it, so a client that disconnects mid-build does not leave its committed change unpublished until the next periodic sync. The periodic job waits one full interval before its first reload because the engine already compiles at startup.

!!! warning "63 active sources maximum"
    One bit is reserved for manually added entries, leaving **63 downloaded sources**. If more than 63 sources are enabled, the 63 lowest-numbered ones are compiled and the rest are **silently skipped** — the only signal is a `WARN` line at startup and after each blocklist refresh. It is a soft cap: the UI and API will happily let you create more.

---

## Allocator and build profile

- **mimalloc** is the global allocator — measurably better than the system allocator for the many small, short-lived allocations of DNS parsing.
- Release builds use fat LTO, a single codegen unit, `panic = "abort"` and no overflow checks.

---

## What you can tune

| Knob | Where | Default |
|:-----|:------|:--------|
| Cache capacity | `[dns] cache_max_entries` | 200,000 |
| Eviction strategy | `[dns] cache_eviction_strategy` | `hit_rate` |
| Cache shards | `[dns] cache_shard_amount` | auto (4 × cores, 8–256) |
| In-flight shards | `[dns] cache_inflight_shards` | auto (2 × cores, 8–128) |
| TTL floor/ceiling | `[dns] cache_min_ttl` / `cache_max_ttl` | 0 / 86400 |
| Optimistic refresh | `[dns] cache_optimistic_refresh` and `cache_refresh_*` | on |
| Query log batching | `[database] query_log_*` | 2000-row batches, 200 ms flush |

Batch size, L1 size, block decision cache size, and socket buffers are fixed at compile time. Worker count can be overridden through `TOKIO_WORKER_THREADS`.

See [Cache Configuration](../configuration/cache.md) for the full reference of the tunable half.
