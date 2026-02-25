use ferrous_dns_application::ports::BlockFilterEnginePort;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct BlocklistSyncJob {
    engine: Arc<dyn BlockFilterEnginePort>,
    interval_secs: u64,
    shutdown: CancellationToken,
}

impl BlocklistSyncJob {
    pub fn new(engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        Self {
            engine,
            interval_secs: 86400,
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
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
                tokio::select! {
                    _ = self.shutdown.cancelled() => {
                        info!("BlocklistSyncJob: shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        info!("BlocklistSyncJob: reloading blocklist sources");
                        match self.engine.reload().await {
                            Ok(()) => info!("BlocklistSyncJob: reload completed successfully"),
                            Err(e) => error!(error = %e, "BlocklistSyncJob: reload failed"),
                        }
                    }
                }
            }
        });
    }
}
