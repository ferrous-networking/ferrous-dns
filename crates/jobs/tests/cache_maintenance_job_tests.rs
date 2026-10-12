use async_trait::async_trait;
use ferrous_dns_application::ports::{CacheCompactionOutcome, CacheMaintenancePort};
use ferrous_dns_domain::DomainError;
use ferrous_dns_jobs::CacheMaintenanceJob;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Default)]
struct MockCacheMaintenancePort {
    eviction_calls: AtomicU64,
    compaction_calls: AtomicU64,
    fail_eviction: AtomicBool,
    fail_compaction: AtomicBool,
}

impl MockCacheMaintenancePort {
    fn failing_eviction() -> Self {
        Self {
            fail_eviction: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn failing_compaction() -> Self {
        Self {
            fail_compaction: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn eviction_call_count(&self) -> u64 {
        self.eviction_calls.load(Ordering::Relaxed)
    }

    fn compaction_call_count(&self) -> u64 {
        self.compaction_calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl CacheMaintenancePort for MockCacheMaintenancePort {
    async fn run_eviction_cycle(&self) -> Result<(), DomainError> {
        self.eviction_calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_eviction.load(Ordering::Relaxed) {
            return Err(DomainError::IoError("mock eviction failure".into()));
        }
        Ok(())
    }

    async fn run_compaction_cycle(&self) -> Result<CacheCompactionOutcome, DomainError> {
        self.compaction_calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_compaction.load(Ordering::Relaxed) {
            return Err(DomainError::IoError("mock compaction failure".into()));
        }
        Ok(CacheCompactionOutcome::default())
    }
}

// Both tasks tick once immediately, so only a second tick proves an interval is honoured.

#[tokio::test]
async fn test_cache_maintenance_job_eviction_runs_on_the_cycle_interval() {
    let mock = Arc::new(MockCacheMaintenancePort::default());
    CacheMaintenanceJob::new(mock.clone(), 1, 3600).spawn();

    sleep(Duration::from_millis(1500)).await;

    assert!(mock.eviction_call_count() >= 2);
    assert_eq!(mock.compaction_call_count(), 1);
}

#[tokio::test]
async fn test_cache_maintenance_job_eviction_error_is_non_fatal() {
    let mock = Arc::new(MockCacheMaintenancePort::failing_eviction());

    CacheMaintenanceJob::new(mock.clone(), 1, 3600).spawn();

    sleep(Duration::from_millis(2200)).await;

    assert!(
        mock.eviction_call_count() >= 2,
        "Job should continue running after eviction errors"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_compaction_runs_on_its_own_interval() {
    let mock = Arc::new(MockCacheMaintenancePort::default());
    CacheMaintenanceJob::new(mock.clone(), 3600, 1).spawn();

    sleep(Duration::from_millis(1500)).await;

    assert!(mock.compaction_call_count() >= 2);
    assert_eq!(mock.eviction_call_count(), 1);
}

#[tokio::test]
async fn test_cache_maintenance_job_compaction_error_is_non_fatal() {
    let mock = Arc::new(MockCacheMaintenancePort::failing_compaction());

    CacheMaintenanceJob::new(mock.clone(), 3600, 1).spawn();

    sleep(Duration::from_millis(2200)).await;

    assert!(
        mock.compaction_call_count() >= 2,
        "Job should continue running after compaction errors"
    );
}
