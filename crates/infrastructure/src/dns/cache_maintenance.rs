use super::cache::negative_cache::negative_ttl;
use super::cache::{
    coarse_clock, CacheKey, CachedAddresses, CachedData, CachedDnssecStatus, ColdThresholds,
    DnsCache, DueRefresh, RefreshRequest, RefreshSchedule, TimerInbox,
};

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheCompactionOutcome, CacheMaintenancePort, DnsResolver, QueryLogRepository,
};
use ferrous_dns_domain::{DnsQuery, DnssecStatus, DomainError, QueryLog, QuerySource};
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

/// Timers one tick of a sweep looks at, so a sweep spreads over seconds
/// rather than holding up the repairs queued behind it.
const SWEEP_BUDGET: usize = 16_384;

/// Why an entry reached the worker.
///
/// `Stale` means a client has already been served a stale answer and is
/// waiting on the real one, so it always goes first. `Due` and `Retry` are
/// renewals on a timer, which may decline an answer that would not extend
/// the entry; see [`RefreshOrigin::retry_in`] for what each gets after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOrigin {
    Stale,
    Due,
    Retry,
}

/// What a renewal that got an answer did with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOutcome {
    /// Stored, and the next timer armed.
    Renewed,
    /// Not stored: it would have ended the entry no later than it already
    /// ends. A caching upstream answers with what is left of its own copy,
    /// and two anycast nodes can be minutes apart; taking a copy that ends
    /// sooner cuts a valid answer short, and one that ends at the same second
    /// is the copy the entry already holds.
    Declined,
    /// Removed: the answer validated as Bogus.
    Removed,
    /// Not stored, and the entry kept as it was: validation could not run,
    /// the answer held nothing to store, or the cache refused it.
    Kept,
}

impl RefreshOrigin {
    /// Seconds from now to the next attempt a renewal on a timer that did
    /// not renew the entry gets, given the life the entry has left.
    ///
    /// A declined answer is tried again a second before expiry, when another
    /// copy upstream may already have rolled over, and if declined again, at
    /// expiry, where any answer is taken: an expired entry never declines, so
    /// that ends it in at most three queries. Every upstream answering
    /// SERVFAIL is usually transient, so a first timer gets one retry halfway
    /// through what is left. Any other case is left to compaction, or to
    /// serve-stale once the entry expires.
    fn retry_in(
        self,
        outcome: &Result<RefreshOutcome, DomainError>,
        remaining_secs: u64,
    ) -> Option<u64> {
        match (self, outcome) {
            (Self::Due, Ok(RefreshOutcome::Declined)) if remaining_secs >= 2 => {
                Some(remaining_secs - 1)
            }
            (Self::Due | Self::Retry, Ok(RefreshOutcome::Declined)) => Some(remaining_secs),
            (Self::Due, Err(DomainError::AllUpstreamsServfail)) if remaining_secs >= 2 => {
                Some(remaining_secs / 2)
            }
            _ => None,
        }
    }
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

    /// Resolves `key` again and stores the answer. A serve-stale repair
    /// has a client waiting and always stores; a renewal on a timer declines
    /// an answer that would not extend a live entry (see
    /// [`RefreshOutcome::Declined`]). An entry in a group's view is resolved
    /// for that group, through the pool routed for it.
    async fn refresh_entry(
        cache: &DnsCache,
        resolver: &dyn DnsResolver,
        query_log: Option<&dyn QueryLogRepository>,
        key: &CacheKey,
        origin: RefreshOrigin,
    ) -> Result<RefreshOutcome, DomainError> {
        let start = Instant::now();
        let domain = key.domain.as_str();
        let record_type = &key.record_type;
        let group_id = (key.view != 0).then(|| i64::from(key.view));

        debug!(
            domain = %domain,
            record_type = %record_type,
            view = key.view,
            "Refreshing cache entry (will revalidate DNSSEC if enabled)"
        );

        let query = DnsQuery::new(domain, *record_type).with_group(group_id);
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
                cache.remove_in(domain, record_type, key.view);
                return Ok(RefreshOutcome::Removed);
            }
            Some(DnssecStatus::Indeterminate) => return Ok(RefreshOutcome::Kept),
            _ => {}
        }

        let new_data = if !resolution.addresses.is_empty() {
            CachedData::IpAddresses(CachedAddresses {
                addresses: Arc::clone(&resolution.addresses),
            })
        } else if let Some(wire_bytes) = &resolution.upstream_wire_data {
            CachedData::WireData(wire_bytes.clone())
        } else {
            return Ok(RefreshOutcome::Kept);
        };
        let dnssec_status = resolution.dnssec_status.map(CachedDnssecStatus::from);
        // An answer without records is NXDOMAIN or NODATA: keeping the entry's
        // old TTL would carry a positive answer's lifetime over to it.
        let ttl = resolution
            .min_ttl
            .unwrap_or_else(|| negative_ttl(resolution.negative_soa_ttl));

        // Only a positive answer to a live entry is declined: past expiry any
        // answer beats a stale one, and a negative TTL is the zone's own.
        if origin != RefreshOrigin::Stale && resolution.min_ttl.is_some() {
            let remaining = cache.remaining_ttl_of(key).unwrap_or(0);
            if remaining > 0 && cache.clamp_ttl(ttl) <= remaining {
                return Ok(RefreshOutcome::Declined);
            }
        }

        if !cache.refresh_record_of(key, Some(ttl), new_data, dnssec_status) {
            return Ok(RefreshOutcome::Kept);
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
                group_id,
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

        Ok(RefreshOutcome::Renewed)
    }

    /// Spawns the worker that renews cache entries.
    ///
    /// It takes serve-stale repairs from `stale_rx`, always first, and the
    /// refresh timers the cache arms in `timers` as it stores and renews
    /// entries. Each second it collects the timers armed since the last tick
    /// and claims those that came due. Up to `MAX_CONCURRENT_REFRESHES`
    /// renewals run at once; when more are due, hot ones (by `thresholds`)
    /// go first. `timers` is `None` with optimistic refresh off, and only
    /// repairs arrive.
    pub fn start_refresh_worker(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        stale_rx: mpsc::Receiver<RefreshRequest>,
        timers: Option<Arc<TimerInbox>>,
        thresholds: ColdThresholds,
    ) {
        let base_sweep_at = cache.max_entries().saturating_mul(SWEEP_FACTOR);
        let worker = RefreshWorker {
            cache,
            resolver,
            query_log,
            thresholds,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REFRESHES)),
            timers,
            schedule: RefreshSchedule::default(),
            stale: VecDeque::new(),
            due: BinaryHeap::new(),
            base_sweep_at,
            sweep_at: base_sweep_at,
            sweep_from: None,
        };
        tokio::spawn(worker.run(stale_rx));
    }
}

struct RefreshWorker {
    cache: Arc<DnsCache>,
    resolver: Arc<dyn DnsResolver>,
    query_log: Option<Arc<dyn QueryLogRepository>>,
    thresholds: ColdThresholds,
    permits: Arc<Semaphore>,
    /// Collected on the tick; arming a timer never wakes this task.
    timers: Option<Arc<TimerInbox>>,
    schedule: RefreshSchedule,
    /// Repairs waiting for a permit, in arrival order.
    stale: VecDeque<RefreshRequest>,
    /// Claimed renewals waiting for a permit, most urgent first.
    due: BinaryHeap<DueRefresh>,
    /// The fewest timers a sweep ever waits for.
    base_sweep_at: usize,
    /// Timer count past which a sweep starts. A cache over its capacity can
    /// hold more live timers than the base, so each sweep sets it from what
    /// it left, which keeps sweeps from running back to back.
    sweep_at: usize,
    /// The second the sweep in progress resumes from.
    sweep_from: Option<u64>,
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
        // In step with the clock the records are stamped with, so a timer
        // fires on its second, not up to a second after it.
        coarse_clock::tick();
        self.collect_timers();
        let now = coarse_clock::coarse_now_secs();
        for timer in self.schedule.take_due(now) {
            if let Some(due) = self.cache.claim_due_refresh(&timer, now, &self.thresholds) {
                self.due.push(due);
            }
        }
        self.sweep_step();
    }

    /// Drops a slice of the timers whose entry is gone. They would cost
    /// nothing when they fire, but under eviction churn they pile up for as
    /// long as the longest TTL.
    fn sweep_step(&mut self) {
        let from = match self.sweep_from {
            Some(from) => from,
            None if self.schedule.len() > self.sweep_at => 0,
            None => return,
        };
        let cache = &self.cache;
        self.sweep_from = self
            .schedule
            .sweep(from, SWEEP_BUDGET, |key| cache.holds(key));
        if self.sweep_from.is_none() {
            self.sweep_at = self
                .base_sweep_at
                .max(self.schedule.len().saturating_mul(SWEEP_FACTOR));
        }
    }

    fn start_next(&mut self, permit: OwnedSemaphorePermit) {
        let (key, origin) = if let Some((domain, record_type, view)) = self.stale.pop_front() {
            (
                CacheKey::new(&domain, record_type).in_view(view),
                RefreshOrigin::Stale,
            )
        } else if let Some(due) = self.due.pop() {
            let now = coarse_clock::coarse_now_secs();
            if !self.cache.start_claimed_refresh(&due.key, now) {
                return;
            }
            let origin = if due.retry {
                RefreshOrigin::Retry
            } else {
                RefreshOrigin::Due
            };
            (due.key, origin)
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
                &key,
                origin,
            )
            .await;
            Self::follow_up(&cache, &key, origin, &outcome);
            drop(permit);
        });
    }

    /// Everything that happens after a renewal, in one place. A renewal that
    /// stored the answer armed the next timer itself. One that did not gets
    /// its one more attempt here, if any, before it lets go of the entry:
    /// arming it while the renewal still holds the entry is what keeps
    /// compaction from arming a second one.
    fn follow_up(
        cache: &DnsCache,
        key: &CacheKey,
        origin: RefreshOrigin,
        outcome: &Result<RefreshOutcome, DomainError>,
    ) {
        let domain = key.domain.as_str();
        match outcome {
            Ok(RefreshOutcome::Renewed) => {
                // `cache_optimistic_refreshes` counts renewals ahead of
                // expiry, not serve-stale repairs.
                if origin != RefreshOrigin::Stale {
                    cache
                        .metrics()
                        .optimistic_refreshes
                        .fetch_add(1, AtomicOrdering::Relaxed);
                }
                debug!(domain = %domain, record_type = %key.record_type, ?origin, "Cache entry refreshed");
                return;
            }
            Ok(other) => {
                debug!(domain = %domain, ?origin, outcome = ?other, "Background refresh left the entry as it was");
            }
            Err(e) => {
                debug!(domain = %domain, ?origin, error = %e, "Background refresh failed");
            }
        }
        let remaining = cache.remaining_ttl_of(key).map_or(0, u64::from);
        if let Some(in_secs) = origin.retry_in(outcome, remaining) {
            cache.schedule_retry(key, in_secs);
        }
        cache.reset_refreshing_of(key);
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
