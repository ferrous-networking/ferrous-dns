use ferrous_dns_application::use_cases::CleanupOldClientsUseCase;
use ferrous_dns_jobs::RetentionJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

mod helpers;
use helpers::{make_client, make_old_client, MockClientRepository};

#[tokio::test]
async fn test_cleanup_removes_old_clients() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),       
            make_old_client(2, "192.168.1.2", 40), 
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); 
    assert_eq!(repo.count().await, 1); 
}

#[tokio::test]
async fn test_cleanup_empty_repository() {
    
    let repo = Arc::new(MockClientRepository::new());
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_preserves_recent_clients() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 1),
            make_old_client(2, "192.168.1.2", 1),
            make_old_client(3, "192.168.1.3", 1),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 3);
}

#[tokio::test]
async fn test_cleanup_boundary_exactly_at_retention_days() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 25), 
            make_old_client(2, "192.168.1.2", 40), 
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_cleanup_all_old_clients() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 60),
            make_old_client(2, "192.168.1.2", 90),
            make_old_client(3, "192.168.1.3", 45),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_with_zero_retention_days() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result = use_case.execute(0).await;

    assert!(result.is_ok());
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_idempotent() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "10.0.0.1", 60),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    let result1 = use_case.execute(30).await;
    let result2 = use_case.execute(30).await;

    assert_eq!(result1.unwrap(), 1);
    assert_eq!(result2.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_retention_job_starts_without_panic() {
    
    let repo = Arc::new(MockClientRepository::new());
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo));
    let job = Arc::new(RetentionJob::new(use_case, 30));

    job.start().await;

    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_retention_job_with_custom_interval_fires() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 60),
        ])
        .await,
    );
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));

    let job = Arc::new(RetentionJob::new(use_case, 30).with_interval(1));

    job.start().await;

    sleep(Duration::from_millis(1100)).await;

    assert_eq!(
        repo.count().await,
        0,
        "RetentionJob should have cleaned up the old client"
    );
}

#[tokio::test]
async fn test_retention_job_preserves_recent_clients() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
        ])
        .await,
    );
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));
    let job = Arc::new(RetentionJob::new(use_case, 30).with_interval(1));

    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    assert_eq!(repo.count().await, 2);
}
