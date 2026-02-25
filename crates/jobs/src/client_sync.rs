use ferrous_dns_application::use_cases::{SyncArpCacheUseCase, SyncHostnamesUseCase};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct ClientSyncJob {
    sync_arp: Arc<SyncArpCacheUseCase>,
    sync_hostnames: Arc<SyncHostnamesUseCase>,
    arp_interval_secs: u64,
    hostname_interval_secs: u64,
    shutdown: CancellationToken,
}

impl ClientSyncJob {
    pub fn new(
        sync_arp: Arc<SyncArpCacheUseCase>,
        sync_hostnames: Arc<SyncHostnamesUseCase>,
    ) -> Self {
        Self {
            sync_arp,
            sync_hostnames,
            arp_interval_secs: 60,
            hostname_interval_secs: 300,
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_intervals(mut self, arp_secs: u64, hostname_secs: u64) -> Self {
        self.arp_interval_secs = arp_secs;
        self.hostname_interval_secs = hostname_secs;
        self
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!("Starting client sync background jobs");

        let arp_job = Arc::clone(&self);
        let arp_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(arp_job.arp_interval_secs));
            loop {
                tokio::select! {
                    _ = arp_shutdown.cancelled() => {
                        info!("ClientSyncJob (arp): shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        if let Err(e) = arp_job.sync_arp.execute().await {
                            error!(error = %e, "ARP sync failed");
                        }
                    }
                }
            }
        });

        let hostname_job = Arc::clone(&self);
        let hostname_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(hostname_job.hostname_interval_secs));
            loop {
                tokio::select! {
                    _ = hostname_shutdown.cancelled() => {
                        info!("ClientSyncJob (hostnames): shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        if let Err(e) = hostname_job.sync_hostnames.execute(50).await {
                            error!(error = %e, "Hostname sync failed");
                        }
                    }
                }
            }
        });
    }
}
