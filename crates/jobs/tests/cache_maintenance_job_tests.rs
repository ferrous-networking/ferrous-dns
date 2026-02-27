use ferrous_dns_application::ports::{CacheCompactionOutcome, CacheRefreshOutcome};
use ferrous_dns_jobs::CacheMaintenanceJob;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;

mod helpers;
use helpers::MockCacheMaintenancePort;

#[tokio::test]
async fn test_cache_maintenance_job_starts_without_panic() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    let job = Arc::new(CacheMaintenanceJob::new(mock));

    job.start().await;

    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_cache_maintenance_job_refresh_fires_on_interval() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    let job = Arc::new(CacheMaintenanceJob::new(mock.clone()).with_intervals(1, 3600));

    job.start().await;

    sleep(Duration::from_millis(1100)).await;

    assert!(
        mock.refresh_call_count() >= 1,
        "Refresh should have fired at least once"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_compaction_fires_on_interval() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    let job = Arc::new(CacheMaintenanceJob::new(mock.clone()).with_intervals(3600, 1));

    job.start().await;

    sleep(Duration::from_millis(1100)).await;

    assert!(
        mock.compaction_call_count() >= 1,
        "Compaction should have fired at least once"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_both_tasks_run_concurrently() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    let job = Arc::new(CacheMaintenanceJob::new(mock.clone()).with_intervals(1, 1));

    job.start().await;

    sleep(Duration::from_millis(1100)).await;

    assert!(
        mock.refresh_call_count() >= 1,
        "Refresh should have fired at least once"
    );
    assert!(
        mock.compaction_call_count() >= 1,
        "Compaction should have fired at least once"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_refresh_error_is_non_fatal() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    mock.set_should_fail_refresh(true).await;

    let job = Arc::new(CacheMaintenanceJob::new(mock.clone()).with_intervals(1, 3600));

    job.start().await;

    sleep(Duration::from_millis(2200)).await;

    assert!(
        mock.refresh_call_count() >= 2,
        "Job should continue running after refresh errors"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_compaction_error_is_non_fatal() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    mock.set_should_fail_compaction(true).await;

    let job = Arc::new(CacheMaintenanceJob::new(mock.clone()).with_intervals(3600, 1));

    job.start().await;

    sleep(Duration::from_millis(2200)).await;

    assert!(
        mock.compaction_call_count() >= 2,
        "Job should continue running after compaction errors"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_shuts_down_on_cancellation() {
    let mock = Arc::new(MockCacheMaintenancePort::new());
    let token = CancellationToken::new();

    let job = Arc::new(
        CacheMaintenanceJob::new(mock.clone())
            .with_intervals(1, 1)
            .with_cancellation(token.clone()),
    );

    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    let count_before = mock.refresh_call_count();
    assert!(count_before >= 1, "Should have fired at least once");

    token.cancel();
    sleep(Duration::from_millis(100)).await;

    let count_after = mock.refresh_call_count();
    sleep(Duration::from_millis(1100)).await;

    assert_eq!(
        mock.refresh_call_count(),
        count_after,
        "Should not fire after cancellation"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_with_custom_intervals() {
    let mock = Arc::new(
        MockCacheMaintenancePort::new()
            .with_refresh_outcome(CacheRefreshOutcome {
                candidates_found: 5,
                refreshed: 3,
                failed: 1,
                cache_size: 100,
            })
            .with_compaction_outcome(CacheCompactionOutcome {
                entries_removed: 2,
                cache_size: 98,
            }),
    );

    let job = Arc::new(CacheMaintenanceJob::new(mock.clone()).with_intervals(1, 1));

    job.start().await;

    sleep(Duration::from_millis(1100)).await;

    assert!(
        mock.refresh_call_count() >= 1,
        "Refresh should have run with custom interval"
    );
    assert!(
        mock.compaction_call_count() >= 1,
        "Compaction should have run with custom interval"
    );
}
