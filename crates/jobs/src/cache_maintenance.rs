use ferrous_dns_application::ports::CacheMaintenancePort;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// How often the eviction cycle runs. Bloom rotation is throttled in
/// multiples of it. Renewals do not depend on it: each cache entry arms its
/// own refresh timer.
pub const MAINTENANCE_INTERVAL_SECS: u64 = 60;

pub struct CacheMaintenanceJob {
    maintenance: Arc<dyn CacheMaintenancePort>,
    cycle_interval_secs: u64,
    compaction_interval_secs: u64,
}

impl CacheMaintenanceJob {
    pub fn new(
        maintenance: Arc<dyn CacheMaintenancePort>,
        cycle_interval_secs: u64,
        compaction_interval_secs: u64,
    ) -> Self {
        Self {
            maintenance,
            cycle_interval_secs,
            compaction_interval_secs,
        }
    }

    pub fn spawn(self) {
        info!("Starting cache maintenance background jobs");

        let Self {
            maintenance,
            cycle_interval_secs,
            compaction_interval_secs,
        } = self;

        let cycle = Arc::clone(&maintenance);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cycle_interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = cycle.run_eviction_cycle().await {
                    error!(error = %e, "Cache eviction cycle failed");
                }
            }
        });

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(compaction_interval_secs));
            loop {
                interval.tick().await;
                match maintenance.run_compaction_cycle().await {
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
        });
    }
}
