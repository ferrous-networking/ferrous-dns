use super::cache::{coarse_clock, CachedAddresses, DnsCache};

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheCompactionOutcome, CacheMaintenancePort, CacheRefreshOutcome, DnsResolver,
    QueryLogRepository,
};
use ferrous_dns_domain::{DnsQuery, DomainError, QueryLog, QuerySource};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::debug;

const BACKPRESSURE_MS_PER_CANDIDATE: u64 = 2;

/// Infrastructure adapter implementing `CacheMaintenancePort`.
pub struct DnsCacheMaintenance {
    cache: Arc<DnsCache>,
    resolver: Arc<dyn DnsResolver>,
    query_log: Option<Arc<dyn QueryLogRepository>>,
}

impl DnsCacheMaintenance {
    pub fn new(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
    ) -> Self {
        Self {
            cache,
            resolver,
            query_log,
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
            Ok(resolution) if !resolution.addresses.is_empty() => {
                let response_time = start.elapsed().as_micros() as u64;

                let dnssec_status: Option<super::cache::DnssecStatus> =
                    resolution.dnssec_status.and_then(|s| s.parse().ok());

                let refreshed = cache.refresh_record(
                    domain,
                    record_type,
                    None,
                    super::cache::CachedData::IpAddresses(CachedAddresses {
                        addresses: Arc::clone(&resolution.addresses),
                    }),
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

        self.cache.rotate_bloom();

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
