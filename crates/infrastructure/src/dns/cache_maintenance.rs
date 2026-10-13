use super::cache::negative_cache::negative_ttl;
use super::cache::{
    coarse_clock, CachedAddresses, CachedData, CachedDnssecStatus, DnsCache, DueRefresh,
    RefreshPriority, RefreshRequest, RefreshSchedule, TimerInbox,
};

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheCompactionOutcome, CacheMaintenancePort, DnsResolver, QueryLogRepository,
};
use ferrous_dns_domain::{DnsQuery, DnssecStatus, DomainError, QueryLog, QuerySource, RecordType};
use std::collections::{BinaryHeap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info};

/// Minimum bloom rotation interval in maintenance cycles. Rotation re-seeds
/// every live key, so this only bounds how often that `O(entries)` pass runs.
const MIN_BLOOM_ROTATION_CYCLES: u64 = 3;

/// Renewals running at once. This bounds the upstream load refreshes put on
/// at any instant, and is the only limit on them: throughput follows what is
/// due, so no cache size outgrows it.
const MAX_CONCURRENT_REFRESHES: usize = 16;

/// Timers held, as a multiple of `cache_max_entries`, before the worker
/// sweeps out those whose entry was evicted or removed.
const SWEEP_FACTOR: usize = 2;

/// Why an entry reached the worker.
///
/// `Stale` means a client has already been served a stale answer and is
/// waiting on the real one, so it always goes first. `Due` and `Retry` are
/// renewals ahead of expiry; only a `Due` one gets a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOrigin {
    Stale,
    Due,
    Retry,
}

/// Infrastructure adapter implementing `CacheMaintenancePort`.
pub struct DnsCacheMaintenance {
    cache: Arc<DnsCache>,
    /// Counts maintenance cycles to throttle bloom rotation.
    bloom_cycle_counter: AtomicU64,
    /// Number of maintenance cycles between bloom rotations.
    bloom_rotation_cycles: u64,
}

impl DnsCacheMaintenance {
    /// Eviction and bloom rotation, run every `cycle_interval_secs`, and
    /// compaction. Renewals do not depend on that cadence: they run on
    /// [`Self::start_refresh_worker`].
    pub fn new(cache: Arc<DnsCache>, cycle_interval_secs: u64) -> Self {
        // Rotation only bounds how long bits left behind by removed keys
        // linger: `rotate_bloom` re-seeds every live entry into the new slot,
        // so an entry's visibility does not depend on this cadence.
        let min_ttl = cache.min_ttl() as u64;
        let interval = cycle_interval_secs.max(1);
        let bloom_rotation_cycles = (min_ttl / interval).max(MIN_BLOOM_ROTATION_CYCLES);

        info!(
            bloom_rotation_cycles,
            min_ttl,
            cycle_interval_secs,
            "Bloom rotation throttled to every {} maintenance cycles (~{} seconds)",
            bloom_rotation_cycles,
            bloom_rotation_cycles * interval,
        );

        Self {
            cache,
            bloom_cycle_counter: AtomicU64::new(0),
            bloom_rotation_cycles,
        }
    }

    /// Resolves `domain` again and stores the answer. `ahead_of_expiry` is a
    /// renewal on a timer, which may decline an answer that would not extend
    /// the entry; a serve-stale repair has a client waiting and always stores.
    async fn refresh_entry(
        cache: &DnsCache,
        resolver: &dyn DnsResolver,
        query_log: Option<&dyn QueryLogRepository>,
        domain: &str,
        record_type: &RecordType,
        ahead_of_expiry: bool,
    ) -> Result<bool, DomainError> {
        let start = Instant::now();

        debug!(
            domain = %domain,
            record_type = %record_type,
            "Refreshing cache entry (will revalidate DNSSEC if enabled)"
        );

        let query = DnsQuery::new(domain, *record_type);
        let resolution = resolver.resolve(&query).await?;
        let response_time = start.elapsed().as_micros() as u64;

        // A Bogus answer is a verdict on the zone: the entry goes rather than
        // being renewed, so under Strict the next query SERVFAILs, not hits.
        // Indeterminate only means validation could not run (a DS or DNSKEY
        // lookup failed). The entry was validated when it was stored, so it
        // keeps serving until its own TTL ends, and is not renewed with an
        // answer nobody validated.
        match resolution.dnssec_status {
            Some(DnssecStatus::Bogus) => {
                cache.remove(domain, record_type);
                return Ok(false);
            }
            Some(DnssecStatus::Indeterminate) => return Ok(false),
            _ => {}
        }

        let new_data = if !resolution.addresses.is_empty() {
            CachedData::IpAddresses(CachedAddresses {
                addresses: Arc::clone(&resolution.addresses),
            })
        } else if let Some(wire_bytes) = &resolution.upstream_wire_data {
            CachedData::WireData(wire_bytes.clone())
        } else {
            return Ok(false);
        };
        let dnssec_status = resolution.dnssec_status.map(CachedDnssecStatus::from);
        // An answer without records is NXDOMAIN or NODATA: keeping the entry's
        // old TTL would carry a positive answer's lifetime over to it.
        let ttl = resolution
            .min_ttl
            .unwrap_or_else(|| negative_ttl(resolution.negative_soa_ttl));

        // A caching upstream answers with what is left of its own copy, and
        // two anycast nodes can be minutes apart. A positive answer that ends
        // sooner than the entry already does would cut a valid answer short,
        // and one that ends at the same time is the copy the entry already
        // holds: renewing with it only starts a chain of ever shorter
        // renewals. Either way, keep the entry and renew it again as it
        // expires, by which time the upstream's copy has rolled over.
        if ahead_of_expiry && resolution.min_ttl.is_some() {
            if let Some(remaining) = cache.get_remaining_ttl(domain, record_type) {
                if ttl.max(cache.min_ttl()) <= remaining {
                    cache.schedule_refresh_in(domain, *record_type, remaining);
                    return Ok(false);
                }
            }
        }

        if !cache.refresh_record(domain, record_type, Some(ttl), new_data, dnssec_status) {
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

    /// Spawns the worker that renews cache entries.
    ///
    /// It takes serve-stale repairs from `stale_rx`, always first, and the
    /// refresh timers the cache arms in `timers` as it stores and renews
    /// entries. Each second it collects the timers armed since the last tick
    /// and claims those that came due. Up to `MAX_CONCURRENT_REFRESHES`
    /// renewals run at once; when more are due, `priority` decides which go
    /// first. `timers` is `None` with optimistic refresh off, and only repairs
    /// arrive.
    pub fn start_refresh_worker(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        stale_rx: mpsc::Receiver<RefreshRequest>,
        timers: Option<Arc<TimerInbox>>,
        priority: RefreshPriority,
    ) {
        let sweep_at = cache.max_entries().saturating_mul(SWEEP_FACTOR);
        let worker = RefreshWorker {
            cache,
            resolver,
            query_log,
            priority,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REFRESHES)),
            timers,
            schedule: RefreshSchedule::default(),
            stale: VecDeque::new(),
            due: BinaryHeap::new(),
            sweep_at,
        };
        tokio::spawn(worker.run(stale_rx));
    }
}

struct RefreshWorker {
    cache: Arc<DnsCache>,
    resolver: Arc<dyn DnsResolver>,
    query_log: Option<Arc<dyn QueryLogRepository>>,
    priority: RefreshPriority,
    permits: Arc<Semaphore>,
    /// Collected on the tick; arming a timer never wakes this task.
    timers: Option<Arc<TimerInbox>>,
    schedule: RefreshSchedule,
    /// Repairs waiting for a permit, in arrival order.
    stale: VecDeque<RefreshRequest>,
    /// Claimed renewals waiting for a permit, most urgent first.
    due: BinaryHeap<DueRefresh>,
    /// Timer count past which the next tick sweeps out orphaned timers.
    sweep_at: usize,
}

impl RefreshWorker {
    async fn run(mut self, mut stale_rx: mpsc::Receiver<RefreshRequest>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut stale_open = true;

        loop {
            let has_work = !self.stale.is_empty() || !self.due.is_empty();
            if !stale_open && !has_work {
                info!("Refresh worker: repair channel closed, shutting down");
                break;
            }

            // `biased` keeps the arms in this order: a repair a client waits
            // on, then what came due, then starting work.
            tokio::select! {
                biased;

                request = stale_rx.recv(), if stale_open => match request {
                    Some(request) => self.stale.push_back(request),
                    None => stale_open = false,
                },

                _ = tick.tick() => self.claim_due(),

                permit = Arc::clone(&self.permits).acquire_owned(), if has_work => {
                    let Ok(permit) = permit else { break };
                    self.start_next(permit);
                }
            }
        }
    }

    /// Registers every timer armed since the last tick.
    fn collect_timers(&mut self) {
        if let Some(timers) = &self.timers {
            let schedule = &mut self.schedule;
            timers.drain(|timer| schedule.register(timer));
        }
    }

    fn claim_due(&mut self) {
        self.collect_timers();
        let now = coarse_clock::coarse_now_secs();
        for timer in self.schedule.take_due(now) {
            if let Some(due) = self.cache.claim_due_refresh(&timer, now, &self.priority) {
                self.due.push(due);
            }
        }

        if self.schedule.len() > self.sweep_at {
            let cache = &self.cache;
            self.schedule.retain(|key| cache.holds(key));
            // A cache over its capacity can hold more live timers than the
            // bound; moving it keeps the sweep from running every second.
            self.sweep_at = self
                .sweep_at
                .max(self.schedule.len().saturating_mul(SWEEP_FACTOR));
        }
    }

    fn start_next(&mut self, permit: OwnedSemaphorePermit) {
        let (domain, record_type, origin) =
            if let Some((domain, record_type)) = self.stale.pop_front() {
                (domain, record_type, RefreshOrigin::Stale)
            } else if let Some(due) = self.due.pop() {
                let now = coarse_clock::coarse_now_secs();
                if !self.cache.is_still_refreshable(&due.key, now) {
                    return;
                }
                let origin = if due.retry {
                    RefreshOrigin::Retry
                } else {
                    RefreshOrigin::Due
                };
                (
                    Arc::from(due.key.domain.as_str()),
                    due.key.record_type,
                    origin,
                )
            } else {
                return;
            };

        let cache = Arc::clone(&self.cache);
        let resolver = Arc::clone(&self.resolver);
        let query_log = self.query_log.clone();
        tokio::spawn(async move {
            let outcome = DnsCacheMaintenance::refresh_entry(
                &cache,
                resolver.as_ref(),
                query_log.as_deref(),
                &domain,
                &record_type,
                origin != RefreshOrigin::Stale,
            )
            .await;
            match outcome {
                Ok(true) => {
                    // `cache_optimistic_refreshes` counts renewals ahead of
                    // expiry, not serve-stale repairs.
                    if origin != RefreshOrigin::Stale {
                        cache
                            .metrics()
                            .optimistic_refreshes
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    debug!(domain = %domain, record_type = %record_type, ?origin, "Cache entry refreshed");
                }
                Ok(false) => cache.reset_refreshing(&domain, &record_type),
                Err(e) => {
                    debug!(domain = %domain, ?origin, error = %e, "Background refresh failed");
                    cache.reset_refreshing(&domain, &record_type);
                    // Every upstream answering SERVFAIL is usually transient,
                    // so a renewal ahead of expiry gets one more try. Any other
                    // failure waits for compaction to re-arm the entry.
                    if origin == RefreshOrigin::Due
                        && matches!(e, DomainError::AllUpstreamsServfail)
                    {
                        cache.schedule_refresh_retry(&domain, record_type);
                    }
                }
            }
            drop(permit);
        });
    }
}

#[async_trait]
impl CacheMaintenancePort for DnsCacheMaintenance {
    async fn run_eviction_cycle(&self) -> Result<(), DomainError> {
        coarse_clock::tick();

        if self.cache.is_over_capacity() {
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

        Ok(())
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
            cache_size: self.cache.len(),
        })
    }
}
