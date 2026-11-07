//! Tests for the Prometheus `/metrics` exposition rendering.
//!
//! These exercise the pure `render_metrics` function with hand-built snapshots,
//! so no `AppState` or database is required.

use ferrous_dns_api::{render_metrics, MetricsInputs};
use ferrous_dns_application::drop_counter::ShedTotals;
use ferrous_dns_application::ports::{
    AggregateStatus, CacheMetricsSnapshot, IpFamily, ResolvedEndpointHealth, UpstreamGroupHealth,
    UpstreamStatus,
};
use ferrous_dns_application::response_counter::ResponseTotals;
use ferrous_dns_application::tls_certificates::TlsListener;
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
        expirations: 5,
        batch_evictions: 8,
        hit_rate: 62.5,
        transient_upstream_errors: 9,
        stale_refresh_drops: 11,
        optimistic_refresh_shed: 13,
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
        queries_dnssec_bogus: 7,
        queries_dns64_synthesized: 3,
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

/// A healthy scrape with no query stats; tests override what they check.
fn inputs<'a>(
    cache: &'a CacheMetricsSnapshot,
    upstreams: &'a [UpstreamGroupHealth],
) -> MetricsInputs<'a> {
    MetricsInputs {
        cache,
        upstreams,
        query_stats: None,
        blocklist_domains: 0,
        shed: ShedTotals::default(),
        responses: ResponseTotals::default(),
        dns_listening: true,
        certificates: &[],
        version: "9.9.9",
    }
}

#[test]
fn render_includes_cache_counters_and_gauges() {
    let (cache, upstreams, stats) = (sample_cache(), sample_upstreams(), sample_stats());
    let body = render_metrics(&MetricsInputs {
        query_stats: Some(&stats),
        blocklist_domains: 1234,
        ..inputs(&cache, &upstreams)
    })
    .unwrap();

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
    let (cache, upstreams, stats) = (sample_cache(), sample_upstreams(), sample_stats());
    let body = render_metrics(&MetricsInputs {
        query_stats: Some(&stats),
        ..inputs(&cache, &upstreams)
    })
    .unwrap();

    assert!(body.contains("ferrousdns_upstream_up{"));
    assert!(body.contains("ferrousdns_upstream_latency_ms{"));
    assert!(body.contains("family=\"ipv4\""));
    // Query-log gauges (24h window).
    assert!(body.contains("ferrousdns_queries 100"));
    assert!(body.contains("ferrousdns_queries_blocked 20"));
    assert!(body.contains("ferrousdns_queries_dnssec_bogus 7"));
    assert!(body.contains("ferrousdns_uptime_seconds 3600"));
    assert!(body.contains("ferrousdns_queries_by_type{record_type=\"A\"} 80"));
    assert!(body.contains("ferrousdns_build_info{version=\"9.9.9\"} 1"));
}

#[test]
fn render_omits_query_gauges_when_stats_missing() {
    let (cache, upstreams) = (sample_cache(), sample_upstreams());
    let body = render_metrics(&MetricsInputs {
        blocklist_domains: 5,
        ..inputs(&cache, &upstreams)
    })
    .unwrap();

    // Live metrics still present even without query stats.
    assert!(body.contains("ferrousdns_cache_hits_total 5"));
    assert!(body.contains("ferrousdns_build_info{version=\"9.9.9\"} 1"));
    // No query-log–derived series when stats are unavailable.
    assert!(!body.contains("ferrousdns_queries"));
    assert!(!body.contains("ferrousdns_uptime_seconds"));
}

#[test]
fn render_includes_responses_by_rcode() {
    let (cache, upstreams) = (sample_cache(), sample_upstreams());
    let body = render_metrics(&MetricsInputs {
        responses: ResponseTotals {
            by_rcode: [90, 1, 4, 3, 0, 2, 5],
        },
        ..inputs(&cache, &upstreams)
    })
    .unwrap();

    assert!(body.contains("# TYPE ferrousdns_responses counter"));
    for line in [
        "ferrousdns_responses_total{rcode=\"NOERROR\"} 90",
        "ferrousdns_responses_total{rcode=\"FORMERR\"} 1",
        "ferrousdns_responses_total{rcode=\"SERVFAIL\"} 4",
        "ferrousdns_responses_total{rcode=\"NXDOMAIN\"} 3",
        "ferrousdns_responses_total{rcode=\"NOTIMP\"} 0",
        "ferrousdns_responses_total{rcode=\"REFUSED\"} 2",
        "ferrousdns_responses_total{rcode=\"OTHER\"} 5",
    ] {
        assert!(body.contains(line), "missing `{line}` in:\n{body}");
    }
}

#[test]
fn render_reports_whether_the_dns_listener_is_serving() {
    let (cache, upstreams) = (sample_cache(), sample_upstreams());

    let up = render_metrics(&inputs(&cache, &upstreams)).unwrap();
    let down = render_metrics(&MetricsInputs {
        dns_listening: false,
        ..inputs(&cache, &upstreams)
    })
    .unwrap();

    assert!(up.contains("# TYPE ferrousdns_dns_listening gauge"));
    assert!(up.contains("\nferrousdns_dns_listening 1\n"), "{up}");
    assert!(down.contains("\nferrousdns_dns_listening 0\n"), "{down}");
}

#[test]
fn render_reports_each_loaded_certificates_expiry_by_listener() {
    let (cache, upstreams) = (sample_cache(), sample_upstreams());
    let certificates = [
        (TlsListener::Web, 1_900_000_000),
        (TlsListener::Dot, 1_800_000_000),
    ];

    let body = render_metrics(&MetricsInputs {
        certificates: &certificates,
        ..inputs(&cache, &upstreams)
    })
    .unwrap();

    assert!(body.contains("# TYPE ferrousdns_tls_cert_not_after_seconds gauge"));
    for line in [
        "ferrousdns_tls_cert_not_after_seconds{listener=\"web\"} 1900000000",
        "ferrousdns_tls_cert_not_after_seconds{listener=\"dot\"} 1800000000",
    ] {
        assert!(body.contains(line), "missing `{line}` in:\n{body}");
    }
    assert!(
        !body.contains("listener=\"doq\""),
        "no certificate, no series"
    );
}

#[test]
fn render_has_no_certificate_series_without_tls() {
    let (cache, upstreams) = (sample_cache(), sample_upstreams());

    let body = render_metrics(&inputs(&cache, &upstreams)).unwrap();

    assert!(
        !body.contains("ferrousdns_tls_cert_not_after_seconds{"),
        "{body}"
    );
}
