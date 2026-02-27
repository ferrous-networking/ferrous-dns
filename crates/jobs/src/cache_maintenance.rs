use ferrous_dns_application::ports::CacheMaintenancePort;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 60;
const DEFAULT_COMPACTION_INTERVAL_SECS: u64 = 600;

pub struct CacheMaintenanceJob {
    maintenance: Arc<dyn CacheMaintenancePort>,
    refresh_interval_secs: u64,
    compaction_interval_secs: u64,
    shutdown: CancellationToken,
}

impl CacheMaintenanceJob {
    pub fn new(maintenance: Arc<dyn CacheMaintenancePort>) -> Self {
        Self {
            maintenance,
            refresh_interval_secs: DEFAULT_REFRESH_INTERVAL_SECS,
            compaction_interval_secs: DEFAULT_COMPACTION_INTERVAL_SECS,
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_intervals(mut self, refresh_secs: u64, compaction_secs: u64) -> Self {
        self.refresh_interval_secs = refresh_secs;
        self.compaction_interval_secs = compaction_secs;
        self
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!("Starting cache maintenance background jobs");

        let refresh_job = Arc::clone(&self);
        let refresh_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(refresh_job.refresh_interval_secs));
            loop {
                tokio::select! {
                    _ = refresh_shutdown.cancelled() => {
                        info!("CacheMaintenanceJob (refresh): shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        match refresh_job.maintenance.run_refresh_cycle().await {
                            Ok(outcome) => {
                                if outcome.candidates_found > 0 {
                                    info!(
                                        candidates = outcome.candidates_found,
                                        refreshed = outcome.refreshed,
                                        failed = outcome.failed,
                                        cache_size = outcome.cache_size,
                                        "Cache refresh cycle completed"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Cache refresh cycle failed");
                            }
                        }
                    }
                }
            }
        });

        let compaction_job = Arc::clone(&self);
        let compaction_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(compaction_job.compaction_interval_secs));
            loop {
                tokio::select! {
                    _ = compaction_shutdown.cancelled() => {
                        info!("CacheMaintenanceJob (compaction): shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        match compaction_job.maintenance.run_compaction_cycle().await {
                            Ok(outcome) => {
                                if outcome.entries_removed > 0 {
                                    info!(
                                        entries_removed = outcome.entries_removed,
                                        cache_size = outcome.cache_size,
                                        "Cache compaction cycle completed"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Cache compaction cycle failed");
                            }
                        }
                    }
                }
            }
        });
    }
}
