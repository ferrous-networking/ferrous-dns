//! Prometheus text-exposition endpoint (`GET /metrics`).
//!
//! Snapshot-based: on each scrape it reads the existing live cache atomics,
//! upstream health, blocklist size, and the (24h-windowed) query-log stats, and
//! renders them as an OpenMetrics/Prometheus exposition. No DNS hot-path
//! instrumentation and no global recorder — the registry is rebuilt per scrape.

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use ferrous_dns_application::ports::{
    AggregateStatus, CacheMetricsSnapshot, IpFamily, UpstreamGroupHealth, UpstreamStatus,
};
use ferrous_dns_domain::QueryStats;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;
use tracing::{debug, instrument, warn};

use crate::state::AppState;

/// Rolling window (hours) for the query-log–derived gauges. Matches the
/// dashboard's default analytics period.
const METRICS_WINDOW_HOURS: f32 = 24.0;

/// OpenMetrics text exposition content type (Prometheus scrapes this fine).
const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct UpstreamLabels {
    pool: String,
    server: String,
    address: String,
    family: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TypeLabels {
    record_type: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: String,
}

fn ip_family_str(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
        IpFamily::Unknown => "unknown",
    }
}

/// Maps an aggregate status to a 1/0 "up" value, or `None` when unknown
/// (no health data yet) so we don't emit a misleading `down`.
fn aggregate_up(status: AggregateStatus) -> Option<i64> {
    match status {
        AggregateStatus::Healthy | AggregateStatus::Partial => Some(1),
        AggregateStatus::Unhealthy => Some(0),
        AggregateStatus::Unknown => None,
    }
}

fn endpoint_up(status: UpstreamStatus) -> Option<i64> {
    match status {
        UpstreamStatus::Healthy => Some(1),
        UpstreamStatus::Unhealthy => Some(0),
        UpstreamStatus::Unknown => None,
    }
}

/// Builds the Prometheus exposition string from already-gathered snapshots.
///
/// Pure and side-effect free so it can be unit-tested without an `AppState` or a
/// database. Cache metrics are monotonic-since-boot atomics → counters; the
/// upstream and query-log values are point-in-time → gauges.
pub fn render_metrics(
    cache: &CacheMetricsSnapshot,
    upstreams: &[UpstreamGroupHealth],
    query_stats: Option<&QueryStats>,
    blocklist_domains: usize,
    version: &str,
) -> String {
    let mut registry = Registry::with_prefix("ferrousdns");

    // --- Cache counters (monotonic since process start) ---
    let cache_counters: [(&str, &str, u64); 10] = [
        ("cache_hits", "DNS cache hits", cache.hits),
        ("cache_misses", "DNS cache misses", cache.misses),
        ("cache_insertions", "DNS cache insertions", cache.insertions),
        ("cache_evictions", "DNS cache evictions", cache.evictions),
        (
            "cache_optimistic_refreshes",
            "DNS cache optimistic background refreshes",
            cache.optimistic_refreshes,
        ),
        (
            "cache_stale_hits",
            "DNS cache hits served from stale entries",
            cache.stale_hits,
        ),
        (
            "cache_lazy_deletions",
            "DNS cache lazy deletions",
            cache.lazy_deletions,
        ),
        (
            "cache_compactions",
            "DNS cache compactions",
            cache.compactions,
        ),
        (
            "cache_batch_evictions",
            "DNS cache batch eviction passes",
            cache.batch_evictions,
        ),
        (
            "cache_transient_upstream_errors",
            "Upstream failures classified as transient (not cached as NXDOMAIN)",
            cache.transient_upstream_errors,
        ),
    ];
    for (name, help, value) in cache_counters {
        let counter = Counter::<u64>::default();
        counter.inc_by(value);
        registry.register(name, help, counter);
    }

    // --- Cache gauges ---
    let cache_entries = Gauge::<i64>::default();
    cache_entries.set(cache.total_entries as i64);
    registry.register(
        "cache_entries",
        "Current DNS cache entry count",
        cache_entries,
    );

    let cache_hit_rate = Gauge::<f64, AtomicU64>::default();
    cache_hit_rate.set(cache.hit_rate);
    registry.register(
        "cache_hit_rate",
        "DNS cache hit rate (percent, since start)",
        cache_hit_rate,
    );

    // --- Upstream health gauges (per resolved endpoint) ---
    let upstream_up = Family::<UpstreamLabels, Gauge>::default();
    let upstream_latency = Family::<UpstreamLabels, Gauge>::default();
    let upstream_failures = Family::<UpstreamLabels, Gauge>::default();
    for group in upstreams {
        // Group-level "up" lives on the configured server address (no per-IP label).
        let group_labels = UpstreamLabels {
            pool: group.pool_name.clone(),
            server: group.address.clone(),
            address: group.address.clone(),
            family: "all".to_string(),
        };
        if let Some(up) = aggregate_up(group.status) {
            upstream_up.get_or_create(&group_labels).set(up);
        }
        for ep in &group.resolved {
            let labels = UpstreamLabels {
                pool: group.pool_name.clone(),
                server: group.address.clone(),
                address: ep.address.clone(),
                family: ip_family_str(ep.family).to_string(),
            };
            if let Some(up) = endpoint_up(ep.status) {
                upstream_up.get_or_create(&labels).set(up);
            }
            if let Some(latency) = ep.latency_ms {
                upstream_latency.get_or_create(&labels).set(latency as i64);
            }
            upstream_failures
                .get_or_create(&labels)
                .set(ep.consecutive_failures as i64);
        }
    }
    registry.register(
        "upstream_up",
        "Upstream endpoint reachable (1) or down (0)",
        upstream_up,
    );
    registry.register(
        "upstream_latency_ms",
        "Last measured upstream endpoint latency in milliseconds",
        upstream_latency,
    );
    registry.register(
        "upstream_consecutive_failures",
        "Consecutive failed health probes per upstream endpoint",
        upstream_failures,
    );

    // --- Blocklist size ---
    let blocklist = Gauge::<i64>::default();
    blocklist.set(blocklist_domains as i64);
    registry.register(
        "blocklist_domains",
        "Number of compiled blocked domains",
        blocklist,
    );

    // --- Query-log–derived gauges (24h rolling window) ---
    if let Some(stats) = query_stats {
        let windowed: [(&str, &str, i64); 7] = [
            (
                "queries",
                "DNS client queries in the last 24h",
                stats.queries_total as i64,
            ),
            (
                "queries_blocked",
                "Blocked DNS client queries in the last 24h",
                stats.queries_blocked as i64,
            ),
            (
                "queries_rate_limited",
                "Rate-limited DNS client queries in the last 24h",
                stats.queries_rate_limited as i64,
            ),
            (
                "queries_malware",
                "Malware/threat-flagged DNS client queries in the last 24h",
                stats.queries_malware_detected as i64,
            ),
            (
                "queries_dnssec_bogus",
                "DNS client queries with a Bogus DNSSEC validation in the last 24h",
                stats.queries_dnssec_bogus as i64,
            ),
            (
                "dns64_synthesized",
                "AAAA answers synthesized by DNS64 (RFC 6147) in the last 24h",
                stats.queries_dns64_synthesized as i64,
            ),
            (
                "unique_clients",
                "Distinct clients seen in the last 24h",
                stats.unique_clients as i64,
            ),
        ];
        for (name, help, value) in windowed {
            let gauge = Gauge::<i64>::default();
            gauge.set(value);
            registry.register(name, help, gauge);
        }

        let avg_gauges: [(&str, &str, f64); 3] = [
            (
                "avg_query_time_ms",
                "Average query response time in milliseconds (last 24h)",
                stats.avg_query_time_ms,
            ),
            (
                "avg_cache_time_ms",
                "Average cache-hit response time in milliseconds (last 24h)",
                stats.avg_cache_time_ms,
            ),
            (
                "avg_upstream_time_ms",
                "Average upstream response time in milliseconds (last 24h)",
                stats.avg_upstream_time_ms,
            ),
        ];
        for (name, help, value) in avg_gauges {
            let gauge = Gauge::<f64, AtomicU64>::default();
            gauge.set(value);
            registry.register(name, help, gauge);
        }

        let uptime = Gauge::<i64>::default();
        uptime.set(stats.uptime_seconds as i64);
        registry.register("uptime_seconds", "Server process uptime in seconds", uptime);

        let by_type = Family::<TypeLabels, Gauge>::default();
        for (record_type, count) in &stats.queries_by_type {
            by_type
                .get_or_create(&TypeLabels {
                    record_type: record_type.as_str().to_string(),
                })
                .set(*count as i64);
        }
        registry.register(
            "queries_by_type",
            "DNS client queries by record type in the last 24h",
            by_type,
        );
    }

    // --- Build info ---
    let build = Family::<BuildLabels, Gauge>::default();
    build
        .get_or_create(&BuildLabels {
            version: version.to_string(),
        })
        .set(1);
    registry.register("build_info", "Build information", build);

    let mut buffer = String::new();
    encode(&mut buffer, &registry).expect("encoding metrics into a String cannot fail");
    buffer
}

#[instrument(skip(state), name = "api_get_metrics")]
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let cache = state.dns.cache.cache_metrics_snapshot();
    let upstreams = state.dns.upstream_health.get_grouped_upstream_health();
    let blocklist_domains = state.blocking.get_block_filter_stats.execute();

    // Query stats come from SQL; if that fails we still serve the live metrics
    // so the scrape endpoint stays up.
    let query_stats = match state.query.get_stats.execute(METRICS_WINDOW_HOURS).await {
        Ok(stats) => Some(stats),
        Err(e) => {
            warn!(error = %e, "Failed to load query stats for /metrics; omitting query gauges");
            None
        }
    };

    debug!("Rendering Prometheus metrics");
    let body = render_metrics(
        &cache,
        &upstreams,
        query_stats.as_ref(),
        blocklist_domains,
        env!("CARGO_PKG_VERSION"),
    );

    ([(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)], body)
}

/// Router exposing a bare, unauthenticated `GET /metrics`.
///
/// Mounted at the top level of the web server (outside the `/api` nest and its
/// auth layer), matching the Prometheus convention of scraping `/metrics`.
pub fn metrics_routes(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}
