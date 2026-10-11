use ferrous_dns_application::use_cases::CleanupOldQueryLogsUseCase;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Cadence of the cleanup, and also the delay before its first run: a cleanup at startup
/// competes with the boot for the disk, and smaller runs hold the write lock for less time.
const RETENTION_INTERVAL_SECS: u64 = 4 * 3600;

pub struct QueryLogRetentionJob {
    cleanup: Arc<CleanupOldQueryLogsUseCase>,
    retention_days: u32,
    interval_secs: u64,
}

impl QueryLogRetentionJob {
    pub fn new(cleanup: Arc<CleanupOldQueryLogsUseCase>, retention_days: u32) -> Self {
        Self {
            cleanup,
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
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            loop {
                interval.tick().await;
                match self.cleanup.execute(self.retention_days).await {
                    Ok(deleted) => info!(deleted, "Query log retention cleanup completed"),
                    Err(e) => error!(error = %e, "Query log retention cleanup failed"),
                }
            }
        });
    }
}
