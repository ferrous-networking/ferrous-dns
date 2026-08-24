use super::cache::{coarse_clock, CachedAddresses, CachedData, DnsCache, RefreshRequest};

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheCompactionOutcome, CacheMaintenancePort, CacheRefreshOutcome, DnsResolver,
    QueryLogRepository,
};
use ferrous_dns_domain::{DnsQuery, DomainError, QueryLog, QuerySource};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info};

/// Minimum bloom rotation interval in refresh cycles. Rotation re-seeds every
/// live key, so this only bounds how often that `O(entries)` pass runs.
const MIN_BLOOM_ROTATION_CYCLES: u64 = 3;
/// Why an entry reached the worker, derived from which queue it arrived on.
///
/// The two service levels are not interchangeable: `Stale` means a client has
/// already been served a stale answer and is waiting on the real one, while
/// `Optimistic` is best-effort prefetching the worker is free to pace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOrigin {
    Stale,
    Optimistic,
}

/// Waits for the pacer to grant a slot, then takes the next optimistic item.
///
/// The order matters twice over. Ticking *before* receiving keeps the arm
/// cancel-safe: `select!` may drop this future when a stale item wins, and the
/// worst that costs is one unused tick, never a dropped message. Ticking
/// *inside* the arm's future rather than after the item is in hand is what
/// keeps the stale arm responsive — the pacer wait happens as part of arm
/// selection, so `select!` is still polling the stale receiver throughout it.
async fn paced_recv(
    pacer: &mut Option<tokio::time::Interval>,
    rx: &mut mpsc::Receiver<RefreshRequest>,
) -> Option<RefreshRequest> {
    if let Some(pacer) = pacer.as_mut() {
        pacer.tick().await;
    }
    rx.recv().await
}

/// Infrastructure adapter implementing `CacheMaintenancePort`.
pub struct DnsCacheMaintenance {
    cache: Arc<DnsCache>,
    /// Counts refresh cycles to throttle bloom rotation.
    bloom_cycle_counter: AtomicU64,
    /// Number of refresh cycles between bloom rotations.
    bloom_rotation_cycles: u64,
}

impl DnsCacheMaintenance {
    pub fn new(cache: Arc<DnsCache>, refresh_interval_secs: u64) -> Self {
        // Rotation only governs how quickly bits left behind by removed keys
        // are purged: `rotate_bloom` re-seeds every live entry into the new
        // slot, so an entry's visibility no longer depends on this cadence.
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

                let dnssec_status: Option<super::cache::CachedDnssecStatus> =
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
                        dns64_synthesized: false,
                        answers: Some(Arc::clone(&resolution.addresses)),
                        upstream_server: resolution.upstream_server.clone(),
                        upstream_pool: resolution.upstream_pool.clone(),
                        response_status: Some("NOERROR"),
                        timestamp: None,
                        query_source: QuerySource::Internal,
                        protocol: None,
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

    /// Spawns the background worker that drains both refresh queues.
    ///
    /// `max_refresh_per_sec` paces **only** the optimistic queue. Those items
    /// arrive in bulk from a maintenance cycle and are best-effort, so draining
    /// them as fast as the upstream answers is exactly what turns one cycle
    /// into a burst of internal queries. `0` disables pacing entirely.
    ///
    /// The stale queue is drained unpaced and is polled first on every
    /// iteration, so a serve-stale repair never waits behind an optimistic
    /// backlog. The task ends when both senders are dropped.
    pub fn start_refresh_worker(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        mut stale_rx: mpsc::Receiver<RefreshRequest>,
        mut optimistic_rx: mpsc::Receiver<RefreshRequest>,
        max_refresh_per_sec: f64,
    ) {
        const MAX_CONCURRENT_REFRESHES: usize = 16;
        /// Ceiling on the pacer period. A rate low enough to exceed it is
        /// already indistinguishable from "off", and this keeps the period
        /// inside what `Duration::from_secs_f64` can represent.
        const MAX_PACER_PERIOD_SECS: f64 = 3600.0;

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REFRESHES));

        let mut pacer = (max_refresh_per_sec > 0.0).then(|| {
            let period = (1.0 / max_refresh_per_sec).min(MAX_PACER_PERIOD_SECS);
            let mut interval = tokio::time::interval(Duration::from_secs_f64(period));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            interval
        });

        tokio::spawn(async move {
            loop {
                // `biased` polls the stale arm first, so a ready serve-stale
                // repair always wins over an optimistic item — including one
                // whose pacer slot came due in the same wakeup.
                let (domain, record_type, origin) = tokio::select! {
                    biased;

                    Some((domain, record_type)) = stale_rx.recv() => {
                        (domain, record_type, RefreshOrigin::Stale)
                    }

                    Some((domain, record_type)) = paced_recv(&mut pacer, &mut optimistic_rx) => {
                        (domain, record_type, RefreshOrigin::Optimistic)
                    }

                    else => {
                        info!("Refresh queue listener: channels closed, shutting down");
                        break;
                    }
                };

                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let cache = Arc::clone(&cache);
                let resolver = Arc::clone(&resolver);
                let query_log = query_log.clone();
                tokio::spawn(async move {
                    match Self::refresh_entry(&cache, &resolver, &query_log, &domain, &record_type)
                        .await
                    {
                        Ok(true) => {
                            // Keeps `cache_optimistic_refreshes` meaning what
                            // it always did: background prefetches, not
                            // serve-stale repairs.
                            if origin == RefreshOrigin::Optimistic {
                                cache
                                    .metrics()
                                    .optimistic_refreshes
                                    .fetch_add(1, AtomicOrdering::Relaxed);
                            }
                            debug!(
                                domain = %domain,
                                record_type = %record_type,
                                ?origin,
                                "Cache entry refreshed"
                            );
                        }
                        Ok(false) => {
                            cache.reset_refreshing(&domain, &record_type);
                        }
                        Err(e) => {
                            debug!(
                                domain = %domain,
                                ?origin,
                                error = %e,
                                "Background refresh failed"
                            );
                            cache.reset_refreshing(&domain, &record_type);
                        }
                    }
                    drop(permit);
                });
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
            let cache_for_bloom = Arc::clone(&self.cache);
            if let Err(e) =
                tokio::task::spawn_blocking(move || cache_for_bloom.rotate_bloom()).await
            {
                debug!(error = %e, "Bloom rotation task panicked");
            }
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

        let candidate_count = candidates.len();

        // The cycle only scans and enqueues; the queue worker performs the
        // refreshes at its configured pace. Doing them inline here is what
        // made a cycle's cost scale with the eligible working set.
        let Some(tx) = self.cache.optimistic_refresh_sender() else {
            // No worker wired up, so nothing would ever drain the queue —
            // release the flags rather than stranding the entries.
            for (domain, record_type) in &candidates {
                self.cache.reset_refreshing(domain, record_type);
            }
            return Ok(CacheRefreshOutcome {
                candidates_found: candidate_count,
                cache_size: self.cache.size(),
                ..Default::default()
            });
        };

        let mut enqueued = 0;
        let mut dropped = 0;

        for (domain, record_type) in &candidates {
            if tx
                .try_send((Arc::from(domain.as_str()), *record_type))
                .is_ok()
            {
                enqueued += 1;
            } else {
                // Queue full: the backlog already outruns the drain rate, so
                // clear the flag and let a later cycle pick the entry up.
                self.cache.reset_refreshing(domain, record_type);
                dropped += 1;
            }
        }

        debug!(
            candidate_count,
            enqueued, dropped, "Optimistic refresh candidates handed to the paced queue"
        );

        Ok(CacheRefreshOutcome {
            candidates_found: candidate_count,
            enqueued,
            dropped,
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
