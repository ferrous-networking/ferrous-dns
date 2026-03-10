use ferrous_dns_application::ports::DgaEvictionTarget;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub struct DgaEvictionJob {
    detector: Arc<dyn DgaEvictionTarget>,
    interval_secs: u64,
    shutdown: CancellationToken,
}

impl DgaEvictionJob {
    pub fn new(detector: Arc<dyn DgaEvictionTarget>, interval_secs: u64) -> Self {
        Self {
            detector,
            interval_secs: interval_secs.max(30),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!(
            interval_secs = self.interval_secs,
            "Starting DGA eviction job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                tokio::select! {
                    _ = self.shutdown.cancelled() => {
                        info!("DgaEvictionJob: shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        self.detector.evict_stale();
                        debug!(
                            tracked = self.detector.tracked_count(),
                            flagged = self.detector.flagged_count(),
                            "DGA eviction cycle"
                        );
                    }
                }
            }
        });
    }
}
