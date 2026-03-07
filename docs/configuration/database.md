# Database Configuration

Ferrous DNS uses **SQLite** for all persistence: query logs, blocklists, clients, groups, settings, and local records. No external database server is required.

---

## Basic Options

```toml
[database]
path = "ferrous-dns.db"
log_queries = true
queries_log_stored = 30
client_tracking_interval = 60
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `path` | `/var/lib/ferrous-dns/ferrous.db` | Path to the SQLite database file |
| `log_queries` | `true` | Store every DNS query for analytics and the query log dashboard |
| `queries_log_stored` | `30` | Days to retain query log entries before automatic cleanup |
| `client_tracking_interval` | `60` | Minimum seconds between consecutive last-seen DB writes per client IP |

---

## Query-Log Write Pipeline

The query log uses an async write pipeline to avoid blocking the DNS hot path. Queries are buffered in a channel and flushed to disk in batches.

```toml
[database]
query_log_channel_capacity = 10000
query_log_max_batch_size = 2000
query_log_flush_interval_ms = 200
query_log_sample_rate = 1
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `query_log_channel_capacity` | `10000` | Channel buffer size (entries). At 100k q/s with `sample_rate=10`, ~200k is needed for a 2s buffer |
| `query_log_max_batch_size` | `2000` | Maximum entries per INSERT transaction. Larger = fewer transactions, higher throughput |
| `query_log_flush_interval_ms` | `200` | Milliseconds between flush cycles |
| `query_log_sample_rate` | `1` | Log 1 out of every N queries. `1` = log all. `10` = log 10% |

**High-throughput tuning** (100k+ q/s):

```toml
query_log_channel_capacity = 200000
query_log_max_batch_size = 5000
query_log_flush_interval_ms = 500
query_log_sample_rate = 10           # log 10% — reduces writes 10x
```

---

## Client Tracking Pipeline

```toml
[database]
client_channel_capacity = 4096
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `client_channel_capacity` | `4096` | Async channel buffer for client last-seen updates |

---

## Connection Pools

Ferrous DNS uses separate connection pools for writes and reads to avoid contention:

```toml
[database]
write_pool_max_connections = 3
read_pool_max_connections = 8
query_log_pool_max_connections = 2
write_busy_timeout_secs = 30
read_busy_timeout_secs = 15
read_acquire_timeout_secs = 15
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `write_pool_max_connections` | `3` | Write pool size. SQLite WAL serialises writers; >3 connections add no throughput |
| `read_pool_max_connections` | `8` | Read pool for dashboard and API endpoints |
| `query_log_pool_max_connections` | `2` | Dedicated read pool for query log endpoint |
| `write_busy_timeout_secs` | `30` | Seconds to wait for the write lock before `SQLITE_BUSY` |
| `read_busy_timeout_secs` | `15` | Seconds to wait for a read connection |
| `read_acquire_timeout_secs` | `15` | Seconds to acquire a connection from the read pool |

---

## SQLite Tuning

```toml
[database]
wal_autocheckpoint = 0
wal_checkpoint_interval_secs = 120
sqlite_cache_size_kb = 16384
sqlite_mmap_size_mb = 64
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `wal_autocheckpoint` | `0` | WAL auto-checkpoint interval (pages). `0` = disabled — manual checkpoints via background job |
| `wal_checkpoint_interval_secs` | `120` | Seconds between background WAL PASSIVE checkpoints |
| `sqlite_cache_size_kb` | `16384` | SQLite page cache size in KB |
| `sqlite_mmap_size_mb` | `64` | Memory-mapped I/O size in MB |

### Recommended Settings by Hardware

| Hardware | `sqlite_cache_size_kb` | `sqlite_mmap_size_mb` | `wal_checkpoint_interval_secs` |
|:---------|:----------------------|:----------------------|:-------------------------------|
| Raspberry Pi (1GB) | `8192` | `32` | `120` |
| Raspberry Pi (2GB+) | `16384` | `32` | `120` |
| Server (SSD, 4GB+) | `32768` | `64` | `300` |
| Server (SSD, 16GB+) | `65536` | `128` | `600` |

### WAL Mode

Ferrous DNS uses SQLite in **WAL (Write-Ahead Logging)** mode, which allows concurrent readers while a write is in progress. This is critical for keeping the dashboard responsive while the query log is being written.

With `wal_autocheckpoint = 0` (default), checkpointing is handled by a background job at `wal_checkpoint_interval_secs` intervals. This avoids sudden I/O spikes under heavy write load.

---

## Database File Location

=== "Docker"

    Mount a persistent volume to `/data/`:
    ```yaml
    volumes:
      - ferrous-data:/data/
    environment:
      - FERROUS_DATABASE=/data/db/ferrous.db
    ```

=== "Binary"

    ```toml
    [database]
    path = "/var/lib/ferrous-dns/ferrous.db"
    ```

!!! warning "SD Card durability"
    On Raspberry Pi with SD cards, reduce write frequency:
    ```toml
    query_log_sample_rate = 10        # log 10% of queries
    client_tracking_interval = 300    # update clients every 5 minutes
    wal_checkpoint_interval_secs = 300
    ```

---

## Logging

```toml
[logging]
level = "info"
```

| Level | Description |
|:------|:------------|
| `error` | Only critical errors |
| `warn` | Warnings and errors |
| `info` | Normal operation (default) |
| `debug` | Detailed operation logs |
| `trace` | Full trace (very verbose, avoid in production) |

```bash
# Override at runtime via environment
FERROUS_LOG_LEVEL=debug ./ferrous-dns
```
