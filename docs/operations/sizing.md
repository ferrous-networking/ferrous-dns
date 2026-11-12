# Sizing

Three things decide what a Ferrous DNS host needs: the blocklists and the cache, which live in memory, and the query log, which lives on disk. CPU is rarely the limit. A cache hit costs well under a microsecond of server time, so see [Benchmarks](../performance/benchmarks.md) only if you serve hundreds of thousands of queries a second.

The figures below were measured on a 64-bit release build: Intel i9-9900KF, 46 GB of RAM, SATA SSD. Memory is the process's anonymous resident memory (`RssAnon` in `/proc/<pid>/status`), so it leaves out the page cache SQLite reads through. Sizes per entry and per row carry over to other 64-bit hosts. Times do not, and a Raspberry Pi was not measured.

An idle server, with no blocklist and an empty cache, uses about **22 MB**. The blocklist table gives the whole process's memory, idle server included; the cache table gives what the cache adds on top.

---

## Blocklists

| List | Entries | Process memory, after a start | Process memory, high-water after a sync |
|:-----|--------:|----------------------:|-------------------------:|
| HaGeZi Pro (adblock format) | 247,757 | 109 MB | 176 MB |
| Plain domains | 1,000,000 | 177 MB | 248 MB |
| Plain domains | 3,000,000 | 406 MB | 606 MB |

**Size for the high-water column.** A sync builds the new index while the old one keeps answering, and the memory it took is not handed back to the system afterwards. The scheduled sync runs once a day, so a long-running server sits at that mark.

Plain domain lists take about 200 MB per million entries at the high-water mark. Adblock lists (`||domain^`) index every rule both as a name and as a wildcard, so they cost more per entry. [Blocking & Filtering](../features/blocking-filtering.md) has figures for the other HaGeZi variants, and its HaGeZi Pro numbers agree with the ones above. On a 1 GB device, stay with the mini and medium Threat lists.

---

## Cache

The cache grows as it fills, up to `cache_max_entries`, and a long-running server keeps it full. When it reaches the limit it evicts down to 90% of it.

| `cache_max_entries` | Entries held when full | Memory, over the idle server |
|--------------------:|-----------------------:|-----------------------------:|
| 50,000 | 45,000 | +33 MB |
| 200,000 (default) | 180,000 | +113 MB |
| 300,000 | 270,000 | +196 MB |

That is roughly 650–750 bytes per entry. On a 1 GB device, `cache_max_entries = 50000` leaves room for a large blocklist. See [Cache](../configuration/cache.md) for what the cache keeps and for how long.

---

## Query log on disk

Each logged query takes about **156 bytes** in the database: 115 for the row and 41 for its index. The per-minute and hourly summaries the dashboard reads add almost nothing. The figure held at 1 and 2 million rows. The file then grows with your average query rate and `queries_log_stored`, the days kept (30 by default):

| Average queries per second | Per day | Kept 30 days |
|---------------------------:|--------:|-------------:|
| 1 | 13 MB | 0.4 GB |
| 10 | 135 MB | 4 GB |
| 50 | 674 MB | 20 GB |
| 100 | 1.35 GB | 40 GB |

Your average is the dashboard's query count for the last 24 hours divided by 86,400 (`ferrousdns_queries / 86400` on [`/metrics`](../features/metrics.md)). Most networks peak at many times their average.

Three settings in `[database]` bring the file down:

| Setting | Effect |
|:--------|:-------|
| `queries_log_stored` | Days kept. The file stops growing once it holds that many days. |
| `query_log_sample_rate` | Logs one query in N. `10` keeps a tenth of the rows, and the dashboard's counts and the 24 h `/metrics` gauges then cover that tenth only. |
| `log_queries = false` | No query log at all. The dashboard's statistics and the 24 h gauges stay empty. |

Either way, `ferrousdns_responses_total` keeps counting every reply, because it is counted where the reply leaves the server, not from the log.

Leave free disk space of about the size of the data for [`--backup-database`](backups-upgrades.md#backing-up-the-database) and `--compact-database`, which both write a full copy.

---

## Restarts

A restart starts with an empty cache. The blocklists come back from the copies the server keeps on disk: the last download of each list, in a `lists` directory beside the database. The server compiles them before it opens any port, DNS or web, so its first answer is already filtered. Once it is serving, it downloads every list again in the background, and a list whose host is down at that moment keeps its copy.

Measured here, a restart answered its first query 0.13–0.19 s after it started with HaGeZi Pro, and 0.32–0.34 s with 1 million entries. Before the copies, the server answered after 0.02 s but left blocked names unfiltered until the lists were in force, 0.3–0.45 s after it started.

A first start has no copies, and neither has a server whose `lists` directory was deleted. It downloads the lists before it opens its ports, which took 0.32 s for HaGeZi Pro from GitHub. That wait is capped at 30 seconds: past it, the ports open, `Blocklists not compiled after 30 s` is logged at `WARN`, and queries go unfiltered until the build ends. On a small device the compile takes longer, and on a first start so does a slow link. The ports stay closed during the wait, as they do while the process restarts, so keep a [second resolver](redundancy.md) to answer in the meantime.

The copies take about the size of the list files on disk: 5 MB for HaGeZi Pro, 31 MB for 1 million entries in hosts format.
