use ferrous_dns_application::ports::ResponseIpFilterEvictionTarget;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Background job that periodically evicts stale C2 IPs from the filter.
pub struct ResponseIpFilterEvictionJob {
    detector: Arc<dyn ResponseIpFilterEvictionTarget>,
    interval_secs: u64,
    shutdown: CancellationToken,
}

impl ResponseIpFilterEvictionJob {
    pub fn new(detector: Arc<dyn ResponseIpFilterEvictionTarget>, interval_secs: u64) -> Self {
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
            "Starting response IP filter eviction job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                tokio::select! {
                    _ = self.shutdown.cancelled() => {
                        info!("ResponseIpFilterEvictionJob: shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        self.detector.evict_stale_ips();
                        debug!(
                            blocked_ips = self.detector.blocked_ip_count(),
                            "Response IP filter eviction cycle"
                        );
                    }
                }
            }
        });
    }
}
