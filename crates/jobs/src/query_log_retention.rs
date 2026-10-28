use ferrous_dns_application::use_cases::{CleanupOldQueryLogsUseCase, ReclaimFreeSpaceUseCase};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Cadence of the cleanup: smaller runs hold the write lock for less time.
const RETENTION_INTERVAL_SECS: u64 = 4 * 3600;

/// Delay before the first run. A cleanup at startup competes with the boot for the disk,
/// but a full interval would let a server restarted every few hours never clean up.
const FIRST_RUN_DELAY_SECS: u64 = 10 * 60;

pub struct QueryLogRetentionJob {
    cleanup: Arc<CleanupOldQueryLogsUseCase>,
    reclaim: Arc<ReclaimFreeSpaceUseCase>,
    retention_days: u32,
    interval_secs: u64,
}

impl QueryLogRetentionJob {
    /// After each cleanup, `reclaim` gives the freed pages back to the database file.
    pub fn new(
        cleanup: Arc<CleanupOldQueryLogsUseCase>,
        reclaim: Arc<ReclaimFreeSpaceUseCase>,
        retention_days: u32,
    ) -> Self {
        Self {
            cleanup,
            reclaim,
            retention_days,
            interval_secs: RETENTION_INTERVAL_SECS,
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs.max(1);
        self
    }

    pub fn spawn(self) {
        info!(
            retention_days = self.retention_days,
            interval_secs = self.interval_secs,
            "Starting query log retention job"
        );

        tokio::spawn(async move {
            let period = Duration::from_secs(self.interval_secs);
            let first_run = Duration::from_secs(FIRST_RUN_DELAY_SECS.min(self.interval_secs));
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + first_run, period);
            loop {
                interval.tick().await;
                match self.cleanup.execute(self.retention_days).await {
                    Ok(deleted) => info!(deleted, "Query log retention cleanup completed"),
                    Err(e) => error!(error = %e, "Query log retention cleanup failed"),
                }
                match self.reclaim.execute().await {
                    Ok(pages) => info!(pages, "Free pages given back to the database file"),
                    Err(e) => error!(error = %e, "Giving free pages back failed"),
                }
            }
        });
    }
}
