use super::cache::{coarse_clock, CachedAddresses, CachedData, DnsCache};

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheCompactionOutcome, CacheMaintenancePort, CacheRefreshOutcome, DnsResolver,
    QueryLogRepository,
};
use ferrous_dns_domain::{DnsQuery, DomainError, QueryLog, QuerySource, RecordType};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, info};

const BACKPRESSURE_MS_PER_CANDIDATE: u64 = 2;

/// Minimum bloom rotation interval in refresh cycles.
/// Ensures bloom entries survive long enough to match cache min_ttl.
const MIN_BLOOM_ROTATION_CYCLES: u64 = 3;

/// Infrastructure adapter implementing `CacheMaintenancePort`.
pub struct DnsCacheMaintenance {
    cache: Arc<DnsCache>,
    resolver: Arc<dyn DnsResolver>,
    query_log: Option<Arc<dyn QueryLogRepository>>,
    /// Counts refresh cycles to throttle bloom rotation.
    bloom_cycle_counter: AtomicU64,
    /// Number of refresh cycles between bloom rotations.
    bloom_rotation_cycles: u64,
}

impl DnsCacheMaintenance {
    pub fn new(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        refresh_interval_secs: u64,
    ) -> Self {
        // Bloom rotation throttled so entries survive ≥ min_ttl seconds.
        // The 2-slot aging bloom survives 1–2 rotations, so entries live
        // N*interval to 2*N*interval seconds.
        let min_ttl = cache.min_ttl() as u64;
        let interval = refresh_interval_secs.max(1);
        let bloom_rotation_cycles = (min_ttl / interval).max(MIN_BLOOM_ROTATION_CYCLES);

        info!(
            bloom_rotation_cycles,
            min_ttl,
            refresh_interval_secs,
            "Bloom rotation throttled to every {} refresh cycles (~{} seconds)",
            bloom_rotation_cycles,
            bloom_rotation_cycles * interval,
        );

        Self {
            cache,
            resolver,
            query_log,
            bloom_cycle_counter: AtomicU64::new(0),
            bloom_rotation_cycles,
        }
    }

    async fn refresh_entry(
        cache: &Arc<DnsCache>,
        resolver: &Arc<dyn DnsResolver>,
        query_log: &Option<Arc<dyn QueryLogRepository>>,
        domain: &str,
        record_type: &ferrous_dns_domain::RecordType,
    ) -> Result<bool, DomainError> {
        let start = Instant::now();

        debug!(
            domain = %domain,
            record_type = %record_type,
            "Refreshing cache entry (will revalidate DNSSEC if enabled)"
        );

        let query = DnsQuery::new(domain, *record_type);

        match resolver.resolve(&query).await {
            Ok(resolution)
                if !resolution.addresses.is_empty() || resolution.upstream_wire_data.is_some() =>
            {
                let response_time = start.elapsed().as_micros() as u64;

                let dnssec_status: Option<super::cache::DnssecStatus> =
                    resolution.dnssec_status.and_then(|s| s.parse().ok());

                let new_data = if !resolution.addresses.is_empty() {
                    CachedData::IpAddresses(CachedAddresses {
                        addresses: Arc::clone(&resolution.addresses),
                    })
                } else if let Some(ref wire_bytes) = resolution.upstream_wire_data {
                    CachedData::WireData(wire_bytes.clone())
                } else {
                    return Ok(false);
                };

                let refreshed = cache.refresh_record(
                    domain,
                    record_type,
                    resolution.min_ttl,
                    new_data,
                    dnssec_status,
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
                        client_hostname: None,
                        blocked: false,
                        response_time_us: Some(response_time),
                        cache_hit: false,
                        cache_refresh: true,
                        dnssec_status: resolution.dnssec_status,
                        upstream_server: resolution.upstream_server.clone(),
                        upstream_pool: resolution.upstream_pool.clone(),
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
                    response_time_us = response_time,
                    "Cache entry refreshed with new DNSSEC validation"
                );

                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Spawns a background task that listens for stale cache keys and refreshes
    /// them immediately upstream. The task ends when the channel sender is dropped.
    pub fn start_stale_listener(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        mut rx: mpsc::Receiver<(Arc<str>, RecordType)>,
    ) {
        const MAX_CONCURRENT_REFRESHES: usize = 16;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REFRESHES));

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Some((domain, record_type)) => {
                        let permit = match semaphore.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let cache = Arc::clone(&cache);
                        let resolver = Arc::clone(&resolver);
                        let query_log = query_log.clone();
                        tokio::spawn(async move {
                            match Self::refresh_entry(
                                &cache,
                                &resolver,
                                &query_log,
                                &domain,
                                &record_type,
                            )
                            .await
                            {
                                Ok(true) => {
                                    debug!(
                                        domain = %domain,
                                        record_type = %record_type,
                                        "Stale entry refreshed immediately"
                                    );
                                }
                                Ok(false) => {
                                    cache.reset_refreshing(&domain, &record_type);
                                }
                                Err(e) => {
                                    debug!(
                                        domain = %domain,
                                        error = %e,
                                        "Stale refresh failed"
                                    );
                                    cache.reset_refreshing(&domain, &record_type);
                                }
                            }
                            drop(permit);
                        });
                    }
                    None => {
                        info!("Stale refresh listener: channel closed, shutting down");
                        break;
                    }
                }
            }
        });
    }
}

#[async_trait]
impl CacheMaintenancePort for DnsCacheMaintenance {
    async fn run_refresh_cycle(&self) -> Result<CacheRefreshOutcome, DomainError> {
        coarse_clock::tick();

        if self
            .cache
            .eviction_pending
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            let cache_for_evict = Arc::clone(&self.cache);
            if let Err(e) =
                tokio::task::spawn_blocking(move || cache_for_evict.evict_entries()).await
            {
                debug!(error = %e, "Eviction task panicked");
            }
        }

        let cycle = self
            .bloom_cycle_counter
            .fetch_add(1, AtomicOrdering::Relaxed)
            + 1;
        if cycle.is_multiple_of(self.bloom_rotation_cycles) {
            self.cache.rotate_bloom();
        }

        let cache_for_scan = Arc::clone(&self.cache);
        let candidates =
            tokio::task::spawn_blocking(move || cache_for_scan.get_refresh_candidates())
                .await
                .unwrap_or_default();

        if candidates.is_empty() {
            return Ok(CacheRefreshOutcome {
                cache_size: self.cache.size(),
                ..Default::default()
            });
        }

        let mut refreshed = 0;
        let mut failed = 0;
        let candidate_count = candidates.len();

        for (domain, record_type) in &candidates {
            match Self::refresh_entry(
                &self.cache,
                &self.resolver,
                &self.query_log,
                domain,
                record_type,
            )
            .await
            {
                Ok(true) => {
                    refreshed += 1;
                    self.cache
                        .metrics()
                        .optimistic_refreshes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(false) => {
                    self.cache.reset_refreshing(domain, record_type);
                }
                Err(_) => {
                    self.cache.reset_refreshing(domain, record_type);
                    failed += 1;
                }
            }
        }

        sleep(Duration::from_millis(
            candidate_count as u64 * BACKPRESSURE_MS_PER_CANDIDATE,
        ))
        .await;

        Ok(CacheRefreshOutcome {
            candidates_found: candidate_count,
            refreshed,
            failed,
            cache_size: self.cache.size(),
        })
    }

    async fn run_compaction_cycle(&self) -> Result<CacheCompactionOutcome, DomainError> {
        let cache_for_compact = Arc::clone(&self.cache);
        let removed = match tokio::task::spawn_blocking(move || cache_for_compact.compact()).await {
            Ok(count) => count,
            Err(e) => {
                debug!(error = %e, "Compaction task panicked");
                0
            }
        };

        Ok(CacheCompactionOutcome {
            entries_removed: removed,
            cache_size: self.cache.size(),
        })
    }
}
