use ferrous_dns_application::ports::BlockFilterEnginePort;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Background job that periodically reloads blocklist sources.
///
/// Follows the same pattern as `RetentionJob`:
///   - `Arc<Self>` spawn so the job owns its state across ticks
///   - First tick consumed immediately so reload does not happen at startup
///     (the engine already compiles during `Repositories::new()`)
///   - Default interval: 24 h (86 400 s)
pub struct BlocklistSyncJob {
    engine: Arc<dyn BlockFilterEnginePort>,
    interval_secs: u64,
}

impl BlocklistSyncJob {
    pub fn new(engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        Self {
            engine,
            interval_secs: 86400,
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!(
            interval_secs = self.interval_secs,
            "Starting blocklist sync job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            interval.tick().await;

            loop {
                interval.tick().await;
                info!("BlocklistSyncJob: reloading blocklist sources");
                match self.engine.reload().await {
                    Ok(()) => info!("BlocklistSyncJob: reload completed successfully"),
                    Err(e) => error!(error = %e, "BlocklistSyncJob: reload failed"),
                }
            }
        });
    }
}
