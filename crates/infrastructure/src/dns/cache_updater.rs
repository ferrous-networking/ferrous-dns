use super::cache::{coarse_clock, DnsCache};
use crate::dns::HickoryDnsResolver;

const REFRESH_ENTRY_DELAY_MS: u64 = 10;
use ferrous_dns_application::ports::{DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, QueryLog, QuerySource};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info};

pub struct CacheUpdater {
    cache: Arc<DnsCache>,
    resolver: Arc<HickoryDnsResolver>,
    query_log: Option<Arc<dyn QueryLogRepository>>,
    update_interval: Duration,
    compaction_interval: Duration,
}

impl CacheUpdater {
    pub fn new(
        cache: Arc<DnsCache>,
        resolver: Arc<HickoryDnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        update_interval_secs: u64,
        compaction_interval_secs: u64,
    ) -> Self {
        Self {
            cache,
            resolver,
            query_log,
            update_interval: Duration::from_secs(update_interval_secs),
            compaction_interval: Duration::from_secs(compaction_interval_secs),
        }
    }

    pub fn start(self) {
        self.start_updater();
        self.start_compaction();
    }

    fn start_updater(&self) {
        let cache = Arc::clone(&self.cache);
        let resolver = Arc::clone(&self.resolver);
        let query_log = self.query_log.clone();
        let update_interval = self.update_interval;

        tokio::spawn(async move {
            info!(
                interval_secs = update_interval.as_secs(),
                "Cache updater started"
            );

            loop {
                sleep(update_interval).await;
                Self::update_cycle(&cache, &resolver, &query_log).await;
            }
        });
    }

    fn start_compaction(&self) {
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
        });
    }

    async fn update_cycle(
        cache: &Arc<DnsCache>,
        resolver: &Arc<HickoryDnsResolver>,
        query_log: &Option<Arc<dyn QueryLogRepository>>,
    ) {
        coarse_clock::tick();
        debug!("Starting cache update cycle");

        if cache
            .eviction_pending
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            cache.evict_entries();
        }

        cache.rotate_bloom();

        let candidates = cache.get_refresh_candidates();

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

        for (domain, record_type) in candidates {
            match Self::refresh_entry(cache, resolver, query_log, &domain, &record_type).await {
                Ok(true) => {
                    refreshed += 1;
                    cache
                        .metrics()
                        .optimistic_refreshes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(false) => {
                    cache.reset_refreshing(&domain, &record_type);
                    debug!(domain = %domain, "No new records to refresh");
                }
                Err(e) => {
                    cache.reset_refreshing(&domain, &record_type);
                    debug!(
                        domain = %domain,
                        record_type = %record_type,
                        error = %e,
                        "Cache refresh skipped (entry may have changed)"
                    );
                    failed += 1;
                }
            }

            sleep(Duration::from_millis(REFRESH_ENTRY_DELAY_MS)).await;
        }

        info!(
            refreshed = refreshed,
            failed = failed,
            cache_size = cache.size(),
            "Cache update cycle completed"
        );
    }

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

    async fn refresh_entry(
        cache: &Arc<DnsCache>,
        resolver: &Arc<HickoryDnsResolver>,
        query_log: &Option<Arc<dyn QueryLogRepository>>,
        domain: &str,
        record_type: &ferrous_dns_domain::RecordType,
    ) -> Result<bool, ferrous_dns_domain::DomainError> {
        let start = Instant::now();

        debug!(
            domain = %domain,
            record_type = %record_type,
            "Refreshing cache entry (will revalidate DNSSEC if enabled)"
        );

        let query = DnsQuery::new(domain, *record_type);

        match resolver.resolve(&query).await {
            Ok(resolution) if !resolution.addresses.is_empty() => {
                let response_time = start.elapsed().as_micros() as u64;

                let dnssec_status: Option<super::cache::DnssecStatus> =
                    resolution.dnssec_status.and_then(|s| s.parse().ok());

                let refreshed = cache.refresh_record(
                    domain,
                    record_type,
                    None,
                    super::cache::CachedData::IpAddresses(Arc::clone(&resolution.addresses)),
                    dnssec_status.map(|_| super::cache::DnssecStatus::Unknown),
                );

                if !refreshed {
                    return Ok(false);
                }

                if let Some(log) = query_log {
                    let log_entry = QueryLog {
                        id: None,
                        domain: Arc::from(domain),
                        record_type: *record_type,
                        client_ip: IpAddr::from([127, 0, 0, 1]),
                        blocked: false,
                        response_time_us: Some(response_time),
                        cache_hit: false,
                        cache_refresh: true,
                        dnssec_status: resolution.dnssec_status,
                        upstream_server: resolution.upstream_server.clone(),
                        response_status: Some("NOERROR"),
                        timestamp: None,
                        query_source: QuerySource::Internal,
                        group_id: None,
                        block_source: None,
                    };

                    if let Err(e) = log.log_query(&log_entry).await {
                        debug!(error = %e, "Failed to log refresh query (non-critical)");
                    }
                }

                debug!(
                    domain = %domain,
                    record_type = %record_type,
                    cache_hit = resolution.cache_hit,
                    dnssec_status = ?resolution.dnssec_status,
                    response_time_ms = response_time,
                    "Cache entry refreshed with new DNSSEC validation"
                );

                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) => Err(e),
        }
    }
}
