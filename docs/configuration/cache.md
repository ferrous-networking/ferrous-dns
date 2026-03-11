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

For most home and office deployments, `"hit_rate"` gives the best results as it preserves entries for frequently visited sites regardless of recency.

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
| `cache_refresh_threshold` | `0.75` | When remaining TTL fraction falls below this, schedule a refresh |
| `cache_min_hit_rate` | `2.0` | Minimum hits/minute to keep an entry alive via refresh |
| `cache_min_frequency` | `10` | Minimum total hits before an entry is eligible for refresh |
| `cache_access_window_secs` | `43200` | Time window (seconds) since last access for refresh eligibility (43200 = 12h) |

**How it works**: When a cached entry's remaining TTL drops below `cache_refresh_threshold x original_ttl`, and the entry meets the minimum hit rate and frequency thresholds, a background task pre-fetches a fresh response. The cached entry continues serving from cache until the refresh completes -- zero latency impact for clients.

!!! note
    `cache_min_ttl` should be >= 240 seconds so the refresh job has time to act before expiry.

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
cache_min_hit_rate          = 1.0             # refresh more entries
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

