use ferrous_dns_application::use_cases::CleanupOldQueryLogsUseCase;
use ferrous_dns_jobs::QueryLogRetentionJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

mod helpers;
use helpers::MockQueryLogRepository;

#[tokio::test]
async fn test_cleanup_removes_old_logs() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("192.168.1.1").await;
    repo.add_old_log("192.168.1.2", 40).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); 
    assert_eq!(repo.count().await, 1); 
}

#[tokio::test]
async fn test_cleanup_empty_repository() {
    let repo = Arc::new(MockQueryLogRepository::new());
    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_preserves_recent_logs() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("10.0.0.1").await;
    repo.add_recent_log("10.0.0.2").await;
    repo.add_recent_log("10.0.0.3").await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 3);
}

#[tokio::test]
async fn test_cleanup_all_old_logs() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 31).await;
    repo.add_old_log("10.0.0.2", 60).await;
    repo.add_old_log("10.0.0.3", 90).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_mixed_logs() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("192.168.1.1").await;
    repo.add_recent_log("192.168.1.2").await;
    repo.add_old_log("192.168.1.3", 40).await;
    repo.add_old_log("192.168.1.4", 55).await;
    repo.add_old_log("192.168.1.5", 100).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.count().await, 2);
}

#[tokio::test]
async fn test_cleanup_with_boundary_unambiguous() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("192.168.1.1", 25).await; 
    repo.add_old_log("192.168.1.2", 40).await; 

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_cleanup_idempotent() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 60).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result1 = use_case.execute(30).await;
    let result2 = use_case.execute(30).await;

    assert_eq!(result1.unwrap(), 1);
    assert_eq!(result2.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_configurable_retention_short() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 3).await; 
    repo.add_old_log("10.0.0.2", 10).await; 

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());
    let result = use_case.execute(7).await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_cleanup_configurable_retention_long() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 60).await; 
    repo.add_old_log("10.0.0.2", 100).await; 

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());
    let result = use_case.execute(90).await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_query_log_retention_job_starts_without_panic() {
    let repo = Arc::new(MockQueryLogRepository::new());
    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 30));

    job.start().await;
    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_query_log_retention_job_fires_and_cleans() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("192.168.1.100", 60).await;

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 30).with_interval(1));

    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    assert_eq!(
        repo.count().await,
        0,
        "QueryLogRetentionJob should have cleaned up the old log"
    );
}

#[tokio::test]
async fn test_query_log_retention_job_preserves_recent_logs() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("192.168.1.1").await;
    repo.add_recent_log("192.168.1.2").await;

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 30).with_interval(1));

    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    assert_eq!(repo.count().await, 2);
}

#[tokio::test]
async fn test_query_log_retention_job_respects_configured_days() {
    
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 3).await; 
    repo.add_old_log("10.0.0.2", 10).await; 

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 7).with_interval(1));

    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    assert_eq!(repo.count().await, 1);
}
