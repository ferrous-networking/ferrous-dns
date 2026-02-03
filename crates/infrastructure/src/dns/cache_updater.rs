use super::cache::DnsCache;
use crate::dns::HickoryDnsResolver;
use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::DnsQuery;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info};

/// Background task manager for cache optimization
pub struct CacheUpdater {
    cache: Arc<DnsCache>,
    resolver: Arc<HickoryDnsResolver>,
    update_interval: Duration,
    compaction_interval: Duration,
}

impl CacheUpdater {
    pub fn new(
        cache: Arc<DnsCache>,
        resolver: Arc<HickoryDnsResolver>,
        update_interval_secs: u64,
        compaction_interval_secs: u64,
    ) -> Self {
        Self {
            cache,
            resolver,
            update_interval: Duration::from_secs(update_interval_secs),
            compaction_interval: Duration::from_secs(compaction_interval_secs),
        }
    }

    /// Start the background updater and compaction tasks
    pub fn start(self) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let updater_handle = self.start_updater();
        let compaction_handle = self.start_compaction();

        (updater_handle, compaction_handle)
    }

    /// Start optimistic refresh task
    fn start_updater(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.cache);
        let resolver = Arc::clone(&self.resolver);
        let update_interval = self.update_interval;

        tokio::spawn(async move {
            info!(
                interval_secs = update_interval.as_secs(),
                "Cache updater started"
            );

            loop {
                sleep(update_interval).await;
                Self::update_cycle(&cache, &resolver).await;
            }
        })
    }

    /// Start background compaction task
    fn start_compaction(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.cache);
        let compaction_interval = self.compaction_interval;

        tokio::spawn(async move {
            info!(
                interval_secs = compaction_interval.as_secs(),
                "Background compaction started"
            );

            loop {
                sleep(compaction_interval).await;
                Self::compaction_cycle(&cache);
            }
        })
    }

    /// Run one update cycle
    async fn update_cycle(cache: &Arc<DnsCache>, resolver: &Arc<HickoryDnsResolver>) {
        debug!("Starting cache update cycle");

        // Get refresh candidates
        let candidates = cache.get_refresh_candidates().await;

        if candidates.is_empty() {
            debug!("No refresh candidates found");
            return;
        }

        info!(
            candidates = candidates.len(),
            strategy = ?cache.strategy(),
            "Refreshing popular cache entries"
        );

        let mut refreshed = 0;
        let mut failed = 0;

        // Refresh each candidate
        for (domain, record_type) in candidates {
            match Self::refresh_entry(cache, resolver, &domain, &record_type).await {
                Ok(true) => {
                    refreshed += 1;
                    cache
                        .metrics()
                        .optimistic_refreshes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(false) => {
                    debug!(domain = %domain, "No new records to refresh");
                }
                Err(e) => {
                    error!(
                        domain = %domain,
                        record_type = %record_type,
                        error = %e,
                        "Failed to refresh cache entry"
                    );
                    failed += 1;
                }
            }

            // Small delay between refreshes to avoid overwhelming upstream
            sleep(Duration::from_millis(10)).await;
        }

        info!(
            refreshed = refreshed,
            failed = failed,
            cache_size = cache.size(),
            "Cache update cycle completed"
        );
    }

    /// Run one compaction cycle
    fn compaction_cycle(cache: &Arc<DnsCache>) {
        debug!("Starting background compaction cycle");

        let removed = cache.compact();

        if removed > 0 {
            info!(
                removed = removed,
                cache_size = cache.size(),
                "Background compaction completed"
            );
        } else {
            debug!("No entries to compact");
        }
    }

    /// Refresh a single cache entry
    async fn refresh_entry(
        cache: &Arc<DnsCache>,
        resolver: &Arc<HickoryDnsResolver>,
        domain: &str,
        record_type: &ferrous_dns_domain::RecordType,
    ) -> Result<bool, ferrous_dns_domain::DomainError> {
        debug!(
            domain = %domain,
            record_type = %record_type,
            "Refreshing cache entry"
        );

        let query = DnsQuery::new(domain.to_string(), record_type.clone());

        match resolver.resolve(&query).await {
            Ok(resolution) if !resolution.addresses.is_empty() => {
                // Insert with default TTL (clone because insert takes ownership)
                cache.insert(domain, record_type, resolution.addresses.clone(), 3600);

                debug!(
                    domain = %domain,
                    record_type = %record_type,
                    cache_hit = resolution.cache_hit,
                    "Cache entry refreshed successfully"
                );

                Ok(true)
            }
            Ok(_) => {
                // No addresses returned
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}
