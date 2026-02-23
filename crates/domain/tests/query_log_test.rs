use ferrous_dns_domain::{QueryStats, RecordType};
use std::collections::HashMap;

#[test]
fn test_query_stats_default_source_fields() {
    let stats = QueryStats::default();
    assert_eq!(stats.queries_cache_hits, 0);
    assert_eq!(stats.queries_upstream, 0);
    assert_eq!(stats.queries_blocked_by_blocklist, 0);
    assert_eq!(stats.queries_blocked_by_managed_domain, 0);
    assert_eq!(stats.queries_blocked_by_regex_filter, 0);
}

#[test]
fn test_query_stats_source_fields_not_altered_by_analytics() {
    let stats = QueryStats {
        queries_cache_hits: 10,
        queries_upstream: 20,
        queries_blocked_by_blocklist: 5,
        queries_blocked_by_managed_domain: 3,
        queries_blocked_by_regex_filter: 2,
        queries_blocked_by_cname_cloaking: 0,
        ..Default::default()
    };

    let mut by_type = HashMap::new();
    by_type.insert(RecordType::A, 100u64);
    let stats = stats.with_analytics(by_type);

    // with_analytics must not touch source fields
    assert_eq!(stats.queries_cache_hits, 10);
    assert_eq!(stats.queries_upstream, 20);
    assert_eq!(stats.queries_blocked_by_blocklist, 5);
    assert_eq!(stats.queries_blocked_by_managed_domain, 3);
    assert_eq!(stats.queries_blocked_by_regex_filter, 2);
}

#[test]
fn test_query_stats_with_analytics() {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 100);
    queries_by_type.insert(RecordType::AAAA, 50);
    queries_by_type.insert(RecordType::MX, 25);

    let stats = QueryStats::default().with_analytics(queries_by_type);

    assert_eq!(stats.most_queried_type, Some(RecordType::A));
    assert_eq!(stats.type_count(RecordType::A), 100);
    assert!((stats.type_percentage(RecordType::A) - 57.14).abs() < 0.1);
}

#[test]
fn test_top_types() {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 100);
    queries_by_type.insert(RecordType::AAAA, 75);
    queries_by_type.insert(RecordType::MX, 50);
    queries_by_type.insert(RecordType::TXT, 25);

    let stats = QueryStats::default().with_analytics(queries_by_type);
    let top_3 = stats.top_types(3);

    assert_eq!(top_3.len(), 3);
    assert_eq!(top_3[0].0, RecordType::A);
    assert_eq!(top_3[1].0, RecordType::AAAA);
    assert_eq!(top_3[2].0, RecordType::MX);
}

#[test]
fn test_distribution_sorted() {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 50);
    queries_by_type.insert(RecordType::AAAA, 100);
    queries_by_type.insert(RecordType::MX, 25);

    let stats = QueryStats::default().with_analytics(queries_by_type);

    assert_eq!(stats.record_type_distribution[0].0, RecordType::AAAA);
    assert_eq!(stats.record_type_distribution[1].0, RecordType::A);
    assert_eq!(stats.record_type_distribution[2].0, RecordType::MX);
}

#[test]
fn test_empty_analytics() {
    let stats = QueryStats::default().with_analytics(HashMap::new());

    assert_eq!(stats.most_queried_type, None);
    assert_eq!(stats.record_type_distribution.len(), 0);
}

#[test]
fn test_query_stats_type_count() {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 100);
    queries_by_type.insert(RecordType::AAAA, 50);

    let stats = QueryStats::default().with_analytics(queries_by_type);

    assert_eq!(stats.type_count(RecordType::A), 100);
    assert_eq!(stats.type_count(RecordType::AAAA), 50);
    assert_eq!(stats.type_count(RecordType::MX), 0);
}

#[test]
fn test_query_stats_type_percentage() {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 100);
    queries_by_type.insert(RecordType::AAAA, 50);

    let stats = QueryStats::default().with_analytics(queries_by_type);

    assert!((stats.type_percentage(RecordType::A) - 66.67).abs() < 0.1);

    assert!((stats.type_percentage(RecordType::AAAA) - 33.33).abs() < 0.1);

    assert_eq!(stats.type_percentage(RecordType::MX), 0.0);
}

#[test]
fn test_query_stats_with_zero_queries() {
    let stats = QueryStats::default().with_analytics(HashMap::new());

    assert_eq!(stats.type_count(RecordType::A), 0);
    assert_eq!(stats.type_percentage(RecordType::A), 0.0);
    assert_eq!(stats.top_types(5).len(), 0);
}

#[test]
fn test_query_stats_single_type() {
    let mut queries_by_type = HashMap::new();
    queries_by_type.insert(RecordType::A, 100);

    let stats = QueryStats::default().with_analytics(queries_by_type);

    assert_eq!(stats.most_queried_type, Some(RecordType::A));
    assert_eq!(stats.type_percentage(RecordType::A), 100.0);
    assert_eq!(stats.record_type_distribution.len(), 1);
}
