use ferrous_dns_application::{
    ports::QueryLogRepository,
    use_cases::queries::{GetQueryStatsUseCase, GetRecentQueriesUseCase},
};
use ferrous_dns_domain::{BlockSource, QueryLog, QuerySource, RecordType};
use std::net::IpAddr;
use std::sync::Arc;

mod helpers;
use helpers::MockQueryLogRepository;

fn make_log(cache_hit: bool, blocked: bool, block_source: Option<BlockSource>) -> QueryLog {
    QueryLog {
        id: None,
        domain: "example.com".into(),
        record_type: RecordType::A,
        client_ip: IpAddr::from([192, 168, 1, 1]),
        client_hostname: None,
        blocked,
        response_time_us: Some(100),
        cache_hit,
        cache_refresh: false,
        dnssec_status: None,
        upstream_server: None,
        response_status: Some("NOERROR"),
        timestamp: None,
        query_source: QuerySource::Client,
        group_id: None,
        block_source,
    }
}

#[tokio::test]
async fn test_get_recent_queries_empty() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    let use_case = GetRecentQueriesUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute(10, 24.0).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_stats_empty() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    let use_case = GetQueryStatsUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute(24.0).await;
    assert!(result.is_ok());
    let stats = result.unwrap();
    assert_eq!(stats.queries_total, 0);
}

#[tokio::test]
async fn test_get_stats_with_cache_and_upstream() {
    let repo = Arc::new(MockQueryLogRepository::new());

    for _ in 0..3 {
        repo.log_query(&make_log(true, false, None)).await.unwrap();
    }
    for _ in 0..2 {
        repo.log_query(&make_log(false, false, None)).await.unwrap();
    }

    let use_case = GetQueryStatsUseCase::new(
        repo.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );
    let stats = use_case.execute(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 5);
    assert_eq!(stats.queries_cache_hits, 3);
    assert_eq!(stats.queries_upstream, 2);
    assert_eq!(stats.queries_blocked, 0);
}

#[tokio::test]
async fn test_get_stats_blocked_sources() {
    let repo = Arc::new(MockQueryLogRepository::new());

    repo.log_query(&make_log(false, true, Some(BlockSource::Blocklist)))
        .await
        .unwrap();
    repo.log_query(&make_log(false, true, Some(BlockSource::ManagedDomain)))
        .await
        .unwrap();
    repo.log_query(&make_log(false, true, Some(BlockSource::ManagedDomain)))
        .await
        .unwrap();
    repo.log_query(&make_log(false, true, Some(BlockSource::RegexFilter)))
        .await
        .unwrap();

    let use_case = GetQueryStatsUseCase::new(
        repo.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );
    let stats = use_case.execute(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 4);
    assert_eq!(stats.queries_blocked_by_blocklist, 1);
    assert_eq!(stats.queries_blocked_by_managed_domain, 2);
    assert_eq!(stats.queries_blocked_by_regex_filter, 1);
    assert_eq!(stats.queries_blocked_by_cname_cloaking, 0);
}

#[tokio::test]
async fn test_get_stats_cname_cloaking_source() {
    let repo = Arc::new(MockQueryLogRepository::new());

    repo.log_query(&make_log(false, true, Some(BlockSource::CnameCloaking)))
        .await
        .unwrap();
    repo.log_query(&make_log(false, true, Some(BlockSource::CnameCloaking)))
        .await
        .unwrap();
    repo.log_query(&make_log(false, true, Some(BlockSource::Blocklist)))
        .await
        .unwrap();

    let use_case = GetQueryStatsUseCase::new(
        repo.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );
    let stats = use_case.execute(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 3);
    assert_eq!(stats.queries_blocked_by_cname_cloaking, 2);
    assert_eq!(stats.queries_blocked_by_blocklist, 1);
}
