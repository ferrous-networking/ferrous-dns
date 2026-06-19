//! Tests for the Prometheus `/metrics` exposition rendering.
//!
//! These exercise the pure `render_metrics` function with hand-built snapshots,
//! so no `AppState` or database is required.

use ferrous_dns_api::render_metrics;
use ferrous_dns_application::ports::{
    AggregateStatus, CacheMetricsSnapshot, IpFamily, ResolvedEndpointHealth, UpstreamGroupHealth,
    UpstreamStatus,
};
use ferrous_dns_domain::{QueryStats, RecordType, UpstreamStrategy};
use std::collections::HashMap;

fn sample_cache() -> CacheMetricsSnapshot {
    CacheMetricsSnapshot {
        total_entries: 42,
        hits: 5,
        misses: 3,
        insertions: 7,
        evictions: 2,
        optimistic_refreshes: 1,
        stale_hits: 4,
        lazy_deletions: 0,
        compactions: 6,
        batch_evictions: 8,
        hit_rate: 62.5,
        transient_upstream_errors: 9,
    }
}

fn sample_upstreams() -> Vec<UpstreamGroupHealth> {
    vec![UpstreamGroupHealth {
        address: "1.1.1.1:53".to_string(),
        status: AggregateStatus::Healthy,
        resolved: vec![ResolvedEndpointHealth {
            address: "1.1.1.1:53".to_string(),
            family: IpFamily::Ipv4,
            status: UpstreamStatus::Healthy,
            latency_ms: Some(12),
            last_error: None,
            consecutive_failures: 0,
        }],
        pool_name: "main".to_string(),
        strategy: UpstreamStrategy::Parallel,
    }]
}

fn sample_stats() -> QueryStats {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 80);
    QueryStats {
        queries_total: 100,
        queries_blocked: 20,
        queries_rate_limited: 2,
        queries_malware_detected: 1,
        unique_clients: 4,
        uptime_seconds: 3600,
        cache_hit_rate: 50.0,
        avg_query_time_ms: 12.5,
        avg_cache_time_ms: 1.2,
        avg_upstream_time_ms: 30.0,
        source_stats: HashMap::new(),
        queries_by_type,
        most_queried_type: Some(RecordType::A),
        record_type_distribution: Vec::new(),
    }
}

#[test]
fn render_includes_cache_counters_and_gauges() {
    let body = render_metrics(
        &sample_cache(),
        &sample_upstreams(),
        Some(&sample_stats()),
        1234,
        "9.9.9",
    );

    // Cache atomics are monotonic since boot → counters (encoder appends `_total`).
    assert!(body.contains("# TYPE ferrousdns_cache_hits counter"));
    assert!(body.contains("ferrousdns_cache_hits_total 5"));
    assert!(body.contains("ferrousdns_cache_transient_upstream_errors_total 9"));
    // Live gauges.
    assert!(body.contains("ferrousdns_cache_entries 42"));
    assert!(body.contains("ferrousdns_cache_hit_rate"));
    assert!(body.contains("ferrousdns_blocklist_domains 1234"));
    // OpenMetrics exposition is terminated by `# EOF`.
    assert!(body.trim_end().ends_with("# EOF"));
}

#[test]
fn render_includes_upstream_and_query_series() {
    let body = render_metrics(
        &sample_cache(),
        &sample_upstreams(),
        Some(&sample_stats()),
        0,
        "9.9.9",
    );

    assert!(body.contains("ferrousdns_upstream_up{"));
    assert!(body.contains("ferrousdns_upstream_latency_ms{"));
    assert!(body.contains("family=\"ipv4\""));
    // Query-log gauges (24h window).
    assert!(body.contains("ferrousdns_queries 100"));
    assert!(body.contains("ferrousdns_queries_blocked 20"));
    assert!(body.contains("ferrousdns_uptime_seconds 3600"));
    assert!(body.contains("ferrousdns_queries_by_type{record_type=\"A\"} 80"));
    assert!(body.contains("ferrousdns_build_info{version=\"9.9.9\"} 1"));
}

#[test]
fn render_omits_query_gauges_when_stats_missing() {
    let body = render_metrics(&sample_cache(), &sample_upstreams(), None, 5, "9.9.9");

    // Live metrics still present even without query stats.
    assert!(body.contains("ferrousdns_cache_hits_total 5"));
    assert!(body.contains("ferrousdns_build_info{version=\"9.9.9\"} 1"));
    // No query-log–derived series when stats are unavailable.
    assert!(!body.contains("ferrousdns_queries"));
    assert!(!body.contains("ferrousdns_uptime_seconds"));
}
