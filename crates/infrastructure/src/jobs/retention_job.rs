use ferrous_dns_application::use_cases::CleanupOldClientsUseCase;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Background job that periodically cleans up old clients (data retention)
pub struct RetentionJob {
    cleanup: Arc<CleanupOldClientsUseCase>,
    retention_days: u32,
    interval_secs: u64,
}

impl RetentionJob {
    pub fn new(cleanup: Arc<CleanupOldClientsUseCase>, retention_days: u32) -> Self {
        Self {
            cleanup,
            retention_days,
            interval_secs: 86400, // Once per day
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!(
            retention_days = self.retention_days,
            "Starting retention cleanup job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                match self.cleanup.execute(self.retention_days).await {
                    Ok(deleted) => {
                        info!(deleted, "Retention cleanup completed");
                    }
                    Err(e) => {
                        error!(error = %e, "Retention cleanup failed");
                    }
                }
            }
        });
    }
}
