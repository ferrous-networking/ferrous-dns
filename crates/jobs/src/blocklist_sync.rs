use ferrous_dns_application::ports::BlockFilterEnginePort;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

const INTERVAL_SECS: u64 = 86400;

pub struct BlocklistSyncJob {
    engine: Arc<dyn BlockFilterEnginePort>,
}

impl BlocklistSyncJob {
    pub fn new(engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        Self { engine }
    }

    pub fn spawn(self) {
        info!(interval_secs = INTERVAL_SECS, "Starting blocklist sync job");

        tokio::spawn(async move {
            // The engine owns startup compilation; the job starts one period later.
            let period = Duration::from_secs(INTERVAL_SECS);
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;
                info!("BlocklistSyncJob: downloading blocklist sources");
                match self.engine.refresh_lists().await {
                    Ok(()) => info!("BlocklistSyncJob: refresh completed successfully"),
                    Err(e) => error!(error = %e, "BlocklistSyncJob: refresh failed"),
                }
            }
        });
    }
}
