# Team Memory Index

Shared memories for the ferrous-dns team (one file per fact, with `name`/`description`/`type` frontmatter).

<!-- Add one line per memory: - [Title](file.md) — one-line hook -->

- [Cache refresh maximizes coverage](cache-refresh-maximize-coverage.md) — never cap total refresh throughput with a fixed rate; bound concurrency instead
- [Adaptive refresh pacer](cache-adaptive-refresh-pacer.md) — why PR #211 paces by backlog and removed `cache_max_refresh_per_sec`
