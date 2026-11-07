# Metrics & Monitoring

Ferrous DNS exposes a Prometheus/OpenMetrics endpoint covering responses by RCODE, cache behaviour, upstream health, blocklist size and query volume.

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

It sits at the top level of the web server — on the same port as the dashboard (`web_port`, default `8080`), *not* under the API base `/ferrous/api/v1`. When `metrics_enabled = false` the route is not registered at all and returns 404.

Responses use the OpenMetrics content type `application/openmetrics-text; version=1.0.0; charset=utf-8`, which both Prometheus and the OpenTelemetry Collector scrape natively.

!!! warning "The endpoint is not authenticated"
    `/metrics` is deliberately mounted outside the API authentication layer, so scrapers do not need a session or an API token. Anyone who can reach the port can read your query volumes, client counts and upstream topology. Expose `web_port` only on a trusted network, or put a reverse proxy in front that restricts `/metrics` by source address.

---

## Exported metrics

Every name is prefixed `ferrousdns_`, and counters carry the OpenMetrics `_total` suffix (`ferrousdns_cache_hits_total`).

### Listeners

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `dns_listening` | gauge | 1 while the plain DNS listener (UDP and TCP) is serving; 0 before it has bound at start, and after it stops. [`GET /health`](../operations/logs-monitoring.md#health-check) answers `503` at 0 |

A server whose DNS listener is down but whose web server is up still answers scrapes, so Prometheus's `up` stays 1. Alert on `ferrousdns_dns_listening == 0` instead.

### Responses

Every reply sent to a client over UDP, TCP, DoT, DoH or DoQ, counted since process start under the RCODE in its header. It is counted where the reply leaves the resolver, so it is exact with the query log on or off.

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `responses{rcode=…}` | counter | Replies sent, by `rcode`: `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED` or `OTHER` |

- A blocked query counts under the RCODE its [block mode](../configuration/blocking.md) answers with: `NOERROR` for a null IP or NODATA, `NXDOMAIN`, or `REFUSED`.
- A truncated reply (TC=1), such as a rate-limit slip, counts as `NOERROR`. A query the rate limiter refuses counts as `REFUSED`.
- BADCOOKIE is an extended RCODE (23) carried in the OPT record, so it counts as `OTHER`.
- A query dropped without a reply (`udp_fallback_shed`, and `upstream_shed` over UDP) is not counted.

The sum over every `rcode` is the total number of replies, so `rate()` of one label over the sum is its share of the traffic.

### Cache

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `cache_hits` | counter | Answers served from cache |
| `cache_misses` | counter | Lookups that had to go upstream |
| `cache_insertions` | counter | Entries written to the cache |
| `cache_evictions` | counter | Entries evicted under pressure |
| `cache_optimistic_refreshes` | counter | Popular entries refreshed before expiry |
| `cache_stale_hits` | counter | Stale entries served while a refresh was queued |
| `cache_optimistic_refresh_shed` | counter | Renewals given up on: a due entry that died waiting for its turn. Sustained non-zero means renewals fall behind what is due |
| `cache_lazy_deletions` | counter | Expired entries reclaimed on access |
| `cache_compactions` | counter | Entries removed by their own timer once expired, positive or negative |
| `cache_batch_evictions` | counter | Batch eviction passes |
| `cache_transient_upstream_errors` | counter | Upstream errors absorbed without failing the query |
| `cache_entries` | gauge | Entries currently held |
| `cache_hit_rate` | gauge | Hit percentage (0–100) since start |

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

### Overload shedding

Work dropped on purpose because a fixed budget was full, counted since process start. Any rise means the server ran out of headroom at that point; zero is normal. These are what tell deliberate shedding apart from packet loss without reading the rate-limited `WARN` lines that report the same totals.

| Metric | Type | Meaning |
|:-------|:-----|:--------|
| `udp_fallback_shed` | counter | UDP queries dropped unanswered because all 8192 slots for queries leaving the inline cache path were taken; the client retries |
| `upstream_shed` | counter | Client queries refused because 4096 queries, over every transport, were already waiting on an upstream; UDP queries are dropped, stream clients get SERVFAIL |
| `query_log_dropped` | counter | Query log entries dropped because the batching channel (`[database] query_log_channel_capacity`) was full; the queries were still answered |

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

If the dashboard runs over HTTPS (`[server.web_tls]`), add `scheme: https`. With the self-signed certificate generated from the UI, give Prometheus a copy of that certificate rather than turning verification off. The certificate is issued to `localhost` and `ferrous-dns`:

```yaml
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/ferrous-dns-upstream.pem   # a copy of tls_cert_path
      server_name: localhost
```

---

## Useful queries

```promql
# Share of replies that were SERVFAIL over the last 5 minutes
sum(rate(ferrousdns_responses_total{rcode="SERVFAIL"}[5m]))
  / sum(rate(ferrousdns_responses_total[5m]))

# Cache hit rate over the last 5 minutes
rate(ferrousdns_cache_hits_total[5m])
  / (rate(ferrousdns_cache_hits_total[5m]) + rate(ferrousdns_cache_misses_total[5m]))

# Any upstream currently down
ferrousdns_upstream_up == 0

# Share of traffic being blocked (24 h window)
ferrousdns_queries_blocked / ferrousdns_queries

# Queries shed in the last 5 minutes, per path
increase(ferrousdns_udp_fallback_shed_total[5m])
increase(ferrousdns_upstream_shed_total[5m])

# Version skew across a fleet
count by (version) (ferrousdns_build_info)
```

Suggested alerts: `ferrousdns_dns_listening == 0` for longer than a start takes, `ferrousdns_upstream_up == 0` for more than a few minutes, a rising share of `SERVFAIL` or `REFUSED` replies, the cache hit rate from the two counters above dropping below its normal band, and any increase in `ferrousdns_udp_fallback_shed_total` or `ferrousdns_upstream_shed_total` (clients went unanswered: upstreams too slow, or traffic beyond what the server can absorb). Alert on rates of the counters rather than on the 24 h gauges: a `delta()` over a rolling 24 h count compares the last minutes with the same minutes a day earlier, not with zero. Ready-made rules for all of these are in [Logs & Monitoring](../operations/logs-monitoring.md#alert-rules).

---

## Related endpoints

| Endpoint | Auth | Purpose |
|:---------|:-----|:--------|
| `/metrics` | None | Prometheus / OpenMetrics scrape |
| `/ferrous/api/v1/dnssec/stats` | Yes | DNSSEC validation counters, including `ds_denials_unproven` |
| `/ferrous/api/v1/openapi.json` | None | OpenAPI description of the REST API |
