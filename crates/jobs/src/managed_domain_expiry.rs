use ferrous_dns_application::use_cases::PurgeExpiredManagedDomainsUseCase;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

const INTERVAL_SECS: u64 = 30;

/// Removes managed domains once their expiry passes, at most 30 s late. The
/// first tick runs at startup, so rules that expired while the server was
/// down go at once.
pub struct ManagedDomainExpiryJob {
    purge: Arc<PurgeExpiredManagedDomainsUseCase>,
}

impl ManagedDomainExpiryJob {
    pub fn new(purge: Arc<PurgeExpiredManagedDomainsUseCase>) -> Self {
        Self { purge }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = INTERVAL_SECS,
            "Starting managed domain expiry job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(INTERVAL_SECS));
            loop {
                interval.tick().await;
                if let Err(e) = self.purge.execute().await {
                    error!(error = %e, "Managed domain expiry failed");
                }
            }
        });
    }
}
