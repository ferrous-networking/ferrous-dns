use ferrous_dns_application::ports::NxdomainHijackProbeTarget;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Background job that periodically evicts stale NXDomain hijack IPs.
pub struct NxdomainHijackEvictionJob {
    detector: Arc<dyn NxdomainHijackProbeTarget>,
    interval_secs: u64,
    shutdown: CancellationToken,
}

impl NxdomainHijackEvictionJob {
    pub fn new(detector: Arc<dyn NxdomainHijackProbeTarget>, interval_secs: u64) -> Self {
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
            "Starting NXDomain hijack eviction job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                tokio::select! {
                    _ = self.shutdown.cancelled() => {
                        info!("NxdomainHijackEvictionJob: shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        self.detector.evict_stale_ips();
                        debug!(
                            hijack_ips = self.detector.hijack_ip_count(),
                            hijacking_upstreams = self.detector.hijacking_upstream_count(),
                            "NXDomain hijack eviction cycle"
                        );
                    }
                }
            }
        });
    }
}
