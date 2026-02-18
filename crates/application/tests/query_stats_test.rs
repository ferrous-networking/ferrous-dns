use ferrous_dns_application::use_cases::queries::{GetQueryStatsUseCase, GetRecentQueriesUseCase};
use std::sync::Arc;

mod helpers;
use helpers::MockQueryLogRepository;

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
