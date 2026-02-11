use ferrous_dns_application::use_cases::queries::{GetQueryStatsUseCase, GetRecentQueriesUseCase};
use std::sync::Arc;

mod helpers;
use helpers::MockQueryLogRepository;

// Estes testes estão simplificados porque MockQueryLogRepository não implementa
// todos os métodos necessários (count(), clear(), get_all_logs(), etc.)

#[tokio::test]
async fn test_get_recent_queries_empty() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    let use_case = GetRecentQueriesUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute(10).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_stats_empty() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    let use_case = GetQueryStatsUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute().await;
    assert!(result.is_ok());
    let stats = result.unwrap();
    assert_eq!(stats.queries_total, 0);
}
