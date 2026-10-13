# Cache Configuration

Ferrous DNS uses a two-level hierarchical cache designed for maximum throughput with minimal latency.

---

## Cache Architecture

```
Query arrives
    │
    ▼
┌─────────────┐
│  L1 Cache   │  Per-thread, lock-free
│  ~100–500   │  Cache hit P99 < 5µs
│  entries    │
└─────┬───────┘
      │ miss
      ▼
┌─────────────┐
│  L2 Cache   │  Shared, sharded across CPU cores
│  up to 200k │  Cache hit P99 < 35µs
│  entries    │
└─────┬───────┘
      │ miss
      ▼
┌─────────────┐
│  In-flight  │  Coalescing: N concurrent queries for
│  Coalescing │  the same domain → 1 upstream request
└─────┬───────┘
      │
      ▼
   Upstream
```

---

## Basic Cache Options

```toml
[dns]
cache_enabled = true
cache_ttl = 7200
cache_min_ttl = 300
cache_max_ttl = 86400
cache_max_entries = 200000
cache_eviction_strategy = "hit_rate"
cache_compaction_interval = 600
cache_batch_eviction_percentage = 0.1
cache_adaptive_thresholds = false
# cache_shard_amount = 512
# cache_inflight_shards = 64
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `cache_enabled` | `true` | Enable the DNS response cache |
| `cache_ttl` | `7200` | Default TTL (seconds) when the upstream record has none |
| `cache_min_ttl` | `300` | Minimum TTL — records with lower TTLs are clamped to this value |
| `cache_max_ttl` | `86400` | Maximum TTL — records with higher TTLs are clamped |
| `cache_max_entries` | `200000` | Maximum entries in L2 cache |
| `cache_eviction_strategy` | `"hit_rate"` | Eviction policy (see below) |
| `cache_compaction_interval` | `600` | Seconds between full compaction runs (removes expired entries) |
| `cache_batch_eviction_percentage` | `0.1` | Fraction of cache evicted in one pass when full (0.1 = 10%) |
| `cache_adaptive_thresholds` | `false` | Auto-tune eviction thresholds based on observed hit rates |
| `cache_shard_amount` | auto | L2 cache shard count; auto-detected as 4x CPU cores, rounded to power of 2 |
| `cache_inflight_shards` | auto | In-flight coalescing map shard count; auto-detected as 2x CPU cores, rounded to power of 2 (min 8, max 128) |

!!! tip "Shard tuning"
    The default auto-detection works well for most cases. Override only if you have a specific reason:
    - Raspberry Pi 4 (4 cores): 16 shards (`cache_shard_amount`), 8 shards (`cache_inflight_shards`)
    - 8-core server: 32 shards / 16 in-flight
    - 16-core server: 64 shards / 32 in-flight
    - High-concurrency (32+ cores): 128–512 shards / 64–128 in-flight

    `cache_inflight_shards` controls the in-flight coalescing map — the structure that deduplicates concurrent upstream requests for the same domain (cache stampede prevention). In-flight entries are transient, so it needs far fewer shards than the main L2 cache.

---

## Eviction Strategies

| Strategy | Description | Best For |
|:---------|:------------|:---------|
| `"hit_rate"` | Evicts entries with the lowest hits-per-minute rate | Default — keeps the most-used entries alive |
| `"lfu"` | Least Frequently Used — evicts entries with fewest total hits | Stable workloads |
| `"lru"` | Least Recently Used — evicts entries not accessed recently | Bursty workloads |
| `"lfu-k"` | LFU-K — scores hit frequency over a sliding window (see LFU-K parameters below) | Workloads whose popular set drifts |

Names are case-insensitive (`hitrate` and `lfuk` are accepted too). Any other value in the config file, such as `"hit-rate"`, runs as `"hit_rate"` with a warning in the log, which is what earlier releases did with it; the API rejects the update.

For most home and office deployments, `"hit_rate"` gives the best results as it preserves entries for frequently visited sites regardless of recency.

Eviction runs on a fixed 60-second maintenance cycle and compaction every `cache_compaction_interval` seconds, whether or not optimistic refresh is enabled. Inserts do not evict, so between cycles the cache can briefly exceed `cache_max_entries`; each cycle that finds it at or over the limit removes `cache_batch_eviction_percentage` of `cache_max_entries`.

The negative-response and DNSSEC-material caches use bounded expiration sampling when full, falling back to an arbitrary eviction if the sample finds no expired entries. Inserting a new entry does not scan the entire live cache. Because the sample covers a fixed slice of the map, expired negative entries elsewhere are reclaimed by the `cache_compaction_interval` sweep instead. DNSSEC material has no periodic sweep: it is keyed per zone, so a re-validated zone replaces its own entry, and only zones that are never queried again keep expired keys until they are evicted.

---

## Optimistic Refresh

Background refresh renews popular entries before they expire, maintaining a high cache hit rate without ever letting hot entries go cold.

```toml
[dns]
cache_optimistic_refresh = true
cache_refresh_threshold = 0.75
cache_min_hit_rate = 2.0
cache_min_frequency = 10
cache_access_window_secs = 43200
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `cache_optimistic_refresh` | `true` | Enable background refresh |
| `cache_refresh_threshold` | `0.75` | Fraction of the TTL elapsed at which an entry is renewed (0.75 = renewed with a quarter of its TTL left) |
| `cache_min_hit_rate` | `2.0` | Hits/minute below which an entry ranks cold when more entries are due than the worker runs at once |
| `cache_min_frequency` | `10` | Lifetime hits below which an entry ranks cold when more entries are due than the worker runs at once |
| `cache_access_window_secs` | `43200` | Time window (seconds) since last access for refresh eligibility (43200 = 12h) |

**How it works**: when an entry is cached or renewed it arms its own refresh timer, and a background worker renews it when the timer comes due. The cached entry keeps serving until the renewal completes -- zero latency impact for clients. Nothing scans the cache to find what is due, so renewal does not depend on any maintenance interval, and an entry is renewed on time whatever its TTL.

**When an entry falls due**: at `cache_refresh_threshold` of its TTL, or 60 seconds before it expires, whichever comes first -- but the 60-second lead never pulls the renewal before half its TTL. A threshold below 0.5 still applies as set. With the default threshold of 0.75:

| TTL | Renewed after | Why |
|:----|:--------------|:----|
| 3600 s | 2700 s | the threshold comes first |
| 200 s | 140 s | 60 s before expiry comes first |
| 100 s | 50 s | 60 s before expiry would be at 40 s, before half the TTL |
| 30 s | 22 s | the threshold; the TTL is shorter than the 60 s lead |

The half-TTL bound keeps a TTL just above a minute from being renewed every few seconds, since each renewal brings the same TTL back. A TTL under a minute is renewed only while clients keep asking for it: after a renewal nobody asked for, it is left to expire, and the next query renews it again. That keeps a 5-second entry asked for once from being renewed every few seconds for the whole access window. Raising `cache_min_ttl` lowers refresh traffic further.

**Load is bounded by concurrency, not by rate**: at most 16 renewals run at once. When more entries fall due together, they wait their turn, so a burst never floods the upstream, and nothing due is dropped because of a rate limit.

**A renewal never shortens an entry**: a caching upstream such as Cloudflare or Quad9 answers with what is left of its own copy, and two of its anycast nodes can be minutes apart. A renewal ahead of expiry that would end the entry sooner than it already ends, or at the same time, is not applied: the entry keeps its answer and is tried once more a second before it expires, when the upstream's copy has usually rolled over. If that attempt does not extend it either, it is renewed at expiry, where any answer is taken: at most three queries, and the entry does not go stale waiting for a client. Once an entry has expired, any answer is taken.

**When a renewal fails**: the cached answer keeps serving until its TTL ends. If every upstream answered SERVFAIL, which is usually transient, a renewal ahead of expiry is retried once, halfway through the life the entry has left. Any other failure (a timeout, REFUSED, a DNSSEC validation that could not run) is retried by the next compaction pass, every `cache_compaction_interval` seconds, for as long as the entry is in use. Clients asking for the entry in the meantime do not trigger extra retries. A renewal whose answer validates as DNSSEC Bogus removes the entry instead.

!!! note "Minimum Hit Rate and Minimum Frequency rank, they do not exclude"
    Every due entry is renewed. `cache_min_hit_rate` and `cache_min_frequency` only come into play when more entries are due at once than the worker runs in parallel: entries that clear both thresholds go first, and within each group the ones closest to being unusable. Neither threshold stops an entry from being renewed. Watch `cache_optimistic_refresh_shed` on `/metrics`: it counts timers that could not be armed in a burst of inserts and entries that died waiting for their turn. A sustained non-zero value means renewals fall behind what is due.

!!! note "Serve-stale repairs go first"
    When an entry has expired but is still inside its stale-serve grace period, the client is handed the stale answer and a repair is queued. A repair always goes ahead of renewals that are merely due, because someone is already waiting on the fresh result. Serve-stale repairs run whenever the cache is enabled, including with `cache_optimistic_refresh = false`; that option only turns off renewal ahead of expiry.

!!! info "Entries outside the access window are not renewed"
    If a cached entry has not been accessed within `cache_access_window_secs` (default 12 hours) when it falls due, it is not renewed — regardless of how many hits it accumulated in the past. The entry is left to expire naturally and is eventually removed by compaction or eviction. This prevents the cache from wasting upstream queries renewing domains that were popular in the past but are no longer being visited (e.g. a travel site accessed once and never again). If the name is asked for again before it expires, it is renewed again on its next due time.

---

## LFU-K Eviction Parameters

When using `hit_rate` or `lfu` strategy, these parameters control the LFU-K scoring algorithm:

```toml
[dns]
cache_min_lfuk_score = 1.5
cache_lfuk_history_size = 10
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `cache_min_lfuk_score` | `1.5` | Minimum score threshold for eviction candidates |
| `cache_lfuk_history_size` | `10` | Number of recent access timestamps tracked per entry |

LFU-K tracks the K most recent access times per entry. The score is computed as a sliding-window frequency, giving more weight to recent accesses than stale ones. This prevents cache pollution by entries that were popular historically but are no longer queried.

---

## Performance Targets

| Metric | Target | Actual |
|:-------|:-------|:-------|
| L1 cache hit P99 | < 5µs | ~1-3µs |
| L2 cache hit P99 | < 35µs | ~10-20µs |
| Cache hit rate (normal use) | > 90% | ~95% |

---

## Memory Sizing

Approximate memory usage for the L2 cache:

| Entries | Approx. RAM |
|:--------|:------------|
| 50,000  | ~25 MB |
| 100,000 | ~50 MB |
| 200,000 | ~100 MB |
| 500,000 | ~250 MB |

For Raspberry Pi or other constrained devices, reduce `cache_max_entries`:

```toml
# Raspberry Pi 4 (1GB RAM)
cache_max_entries = 50000
```

---

## Configuration by Hardware

The right cache settings depend on available RAM and CPU cores. Use the profile that matches your deployment.

---

### Raspberry Pi / Embedded (≤ 1 GB RAM, 4 cores)

```toml
[dns]
# Cache
cache_enabled                   = true
cache_ttl                       = 7200
cache_min_ttl                   = 300
cache_max_ttl                   = 86400
cache_max_entries               = 25000     # ~12 MB RAM
cache_eviction_strategy         = "lru"    # cheaper on ARM — no frequency tracking
cache_compaction_interval       = 900
cache_batch_eviction_percentage = 0.15
cache_shard_amount              = 16       # 4 cores × 4

# Optimistic refresh off — save CPU and upstream traffic
cache_optimistic_refresh = false
```

**Why `lru` on ARM?** The `hit_rate` and `lfu` strategies track per-entry access frequency, which requires maintaining timestamps. On low-power ARM CPUs, this adds measurable overhead. `lru` is simpler and has near-zero CPU cost.

**Why 25,000 entries?** Each cache entry uses approximately 500 bytes on average. 25,000 entries = ~12 MB, well within the 512 MB–1 GB available after the OS, Ferrous DNS process, and SQLite overhead.

---

### Home Server / Mini PC (2–8 GB RAM, 4–8 cores)

```toml
[dns]
# Cache
cache_enabled                   = true
cache_ttl                       = 7200
cache_min_ttl                   = 300
cache_max_ttl                   = 86400
cache_max_entries               = 100000   # ~50 MB RAM
cache_eviction_strategy         = "hit_rate"
cache_compaction_interval       = 600
cache_batch_eviction_percentage = 0.10
# cache_shard_amount auto (4 × CPU cores)

# Optimistic refresh — keeps popular domains from ever expiring
cache_optimistic_refresh    = true
cache_refresh_threshold     = 0.75
cache_min_hit_rate          = 2.0
cache_min_frequency         = 10
cache_access_window_secs    = 43200        # 12 hours

# LFU-K
cache_min_lfuk_score    = 1.5
cache_lfuk_history_size = 10
```

This is the default recommended profile. It gives a strong hit rate for a typical household (50–200 devices, 500–5,000 distinct domains per day) with roughly 50 MB of RAM dedicated to the cache.

---

### High-Performance Server (16+ GB RAM, 8+ cores)

```toml
[dns]
# Cache
cache_enabled                   = true
cache_ttl                       = 7200
cache_min_ttl                   = 60           # allow short TTLs for dynamic CDN records
cache_max_ttl                   = 86400
cache_max_entries               = 500000       # ~250 MB RAM
cache_eviction_strategy         = "hit_rate"
cache_compaction_interval       = 300
cache_batch_eviction_percentage = 0.05
cache_shard_amount              = 256          # explicit — 16-core × 16
cache_adaptive_thresholds       = true         # auto-tune eviction thresholds

# Aggressive optimistic refresh
cache_optimistic_refresh    = true
cache_refresh_threshold     = 0.80            # refresh at 80% TTL consumed
cache_min_hit_rate          = 1.0             # rank more entries as hot under load
cache_min_frequency         = 5
cache_access_window_secs    = 86400           # 24 hours

# LFU-K
cache_min_lfuk_score    = 1.0
cache_lfuk_history_size = 20                  # more history = better scoring
```

With 500,000 entries and aggressive prefetch enabled, the effective cache hit rate approaches 99% for networks with stable query patterns. The larger `cache_lfuk_history_size` gives the scoring algorithm more data points to distinguish genuinely popular domains from one-time lookups.

---

## Quick Reference

| Hardware | `cache_max_entries` | `cache_eviction_strategy` | `cache_shard_amount` | RAM used |
|:---------|--------------------:|:--------------------------|---------------------:|---------:|
| Raspberry Pi (512 MB) | 10,000 | `lru` | 8 | ~5 MB |
| Raspberry Pi (1 GB) | 25,000 | `lru` | 16 | ~12 MB |
| Mini PC (2–4 GB) | 50,000 | `hit_rate` | auto | ~25 MB |
| Home server (4–8 GB) | 100,000 | `hit_rate` | auto | ~50 MB |
| Server (16+ GB) | 500,000 | `hit_rate` | 256 | ~250 MB |
