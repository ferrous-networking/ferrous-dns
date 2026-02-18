use ferrous_dns_application::use_cases::CleanupOldQueryLogsUseCase;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

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
            interval_secs: 86400,
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!(
            retention_days = self.retention_days,
            "Starting query log retention job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                match self.cleanup.execute(self.retention_days).await {
                    Ok(deleted) => {
                        info!(deleted, "Query log retention cleanup completed");
                    }
                    Err(e) => {
                        error!(error = %e, "Query log retention cleanup failed");
                    }
                }
            }
        });
    }
}
