# Metrics & Monitoring

Ferrous DNS exposes a Prometheus/OpenMetrics endpoint covering cache behaviour, upstream health, blocklist size and query volume.

---

## Enabling the endpoint

Metrics are **off by default**. Turn them on in the `[server]` section:

```toml
[server]
metrics_enabled = true
```

The endpoint is then served at:

```
GET http://<host>:<web_port>/metrics
```

It sits at the top level of the web server — on the same port as the dashboard (`web_port`, default `8080`), *not* under `/api` or `/ferrous/api`. When `metrics_enabled = false` the route is not registered at all and returns 404.

Responses use the OpenMetrics content type `application/openmetrics-text; version=1.0.0; charset=utf-8`, which both Prometheus and the OpenTelemetry Collector scrape natively.

!!! warning "The endpoint is not authenticated"
    `/metrics` is deliberately mounted outside the API authentication layer, so scrapers do not need a session or an API token. Anyone who can reach the port can read your query volumes, client counts and upstream topology. Expose `web_port` only on a trusted network, or put a reverse proxy in front that restricts `/metrics` by source address.

---

## Exported metrics

Every name is prefixed `ferrousdns_`, and counters carry the OpenMetrics `_total` suffix (`ferrousdns_cache_hits_total`).

### Cache

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `cache_hits` | counter | Answers served from cache |
| `cache_misses` | counter | Lookups that had to go upstream |
| `cache_insertions` | counter | Entries written to the cache |
| `cache_evictions` | counter | Entries evicted under pressure |
| `cache_optimistic_refreshes` | counter | Popular entries refreshed before expiry |
| `cache_stale_hits` | counter | Stale entries served while a refresh was queued |
| `cache_lazy_deletions` | counter | Expired entries reclaimed on access |
| `cache_compactions` | counter | Compaction passes |
| `cache_batch_evictions` | counter | Batch eviction passes |
| `cache_transient_upstream_errors` | counter | Upstream errors absorbed without failing the query |
| `cache_entries` | gauge | Entries currently held |
| `cache_hit_rate` | gauge | Hit ratio since start |

### Upstreams

Labelled `{pool, server, address, family}`. The aggregate row for a server uses `family="all"`.

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `upstream_up` | gauge | 1 when the health check considers the server usable |
| `upstream_latency_ms` | gauge | Last observed probe latency |
| `upstream_consecutive_failures` | gauge | Failures since the last success |

### Blocking

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `blocklist_domains` | gauge | Domains currently compiled into the block filter |

### Query volume (rolling 24 h)

These are derived from the SQLite query log over a **24-hour window**, not since process start.

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `queries` | gauge | Queries handled |
| `queries_blocked` | gauge | Answers blocked |
| `queries_rate_limited` | gauge | Queries refused or slipped by the rate limiter |
| `queries_malware` | gauge | Queries flagged by threat detection |
| `queries_dnssec_bogus` | gauge | Answers that failed DNSSEC validation |
| `dns64_synthesized` | gauge | AAAA answers synthesized by DNS64 |
| `unique_clients` | gauge | Distinct clients seen |
| `avg_query_time_ms` | gauge | Mean end-to-end query time |
| `avg_cache_time_ms` | gauge | Mean time for cache-served answers |
| `avg_upstream_time_ms` | gauge | Mean time for upstream-served answers |
| `uptime_seconds` | gauge | Process uptime |
| `queries_by_type{record_type=…}` | gauge | Queries per record type |

!!! note "Query-log metrics can be absent"
    If the statistics query against SQLite fails, this whole group is omitted and the scrape still returns 200 with the remaining families. Alert on the *absence* of `ferrousdns_queries` rather than assuming zero.

### Build

`ferrousdns_build_info{version="…"}` is always `1` — useful for `count by (version)` across a fleet, and for confirming which build a scrape target is running.

---

## Scrape configuration

```yaml
scrape_configs:
  - job_name: ferrous-dns
    static_configs:
      - targets: ["ferrous-dns.internal:8080"]
```

If the dashboard runs over HTTPS (`[server.web_tls]`), add `scheme: https` — and `tls_config.insecure_skip_verify: true` when using the self-signed certificate generated from the UI.

---

## Useful queries

```promql
# Cache hit rate over the last 5 minutes
rate(ferrousdns_cache_hits_total[5m])
  / (rate(ferrousdns_cache_hits_total[5m]) + rate(ferrousdns_cache_misses_total[5m]))

# Any upstream currently down
ferrousdns_upstream_up == 0

# Share of traffic being blocked (24 h window)
ferrousdns_queries_blocked / ferrousdns_queries

# Version skew across a fleet
count by (version) (ferrousdns_build_info)
```

Suggested alerts: `ferrousdns_upstream_up == 0` for more than a few minutes, `ferrousdns_cache_hit_rate` dropping below its normal band, and a rising `ferrousdns_queries_rate_limited` (either an attack or a rate limit set too tight).

---

## Related endpoints

| Endpoint | Auth | Purpose |
|:---------|:-----|:--------|
| `/metrics` | None | Prometheus / OpenMetrics scrape |
| `/api/dnssec/stats` | Yes | DNSSEC validation counters, including `ds_denial_fail_opens` |
| `/openapi.json` | None | OpenAPI description of the REST API |
