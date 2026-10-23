use super::cache::negative_cache::negative_ttl;
use super::cache::{
    coarse_clock, CacheKey, CachedAddresses, CachedData, CachedDnssecStatus, ColdThresholds,
    DnsCache, DueRefresh, RefreshRequest, RefreshSchedule, SweepFrom, TimerInbox, TimerKind,
};

use ferrous_dns_application::ports::{DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DnssecStatus, DomainError, QueryLog, QuerySource};
use std::collections::{BinaryHeap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info};

/// Bloom rotation runs every `cache_min_ttl`, in whole minutes, and at least
/// this many minutes apart. Rotation re-seeds every live key, so this only
/// bounds how often that `O(entries)` pass runs.
const MIN_BLOOM_ROTATION_MINUTES: u64 = 3;

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
    /// through what is left. Any other case waits `cache_compaction_interval`
    /// for its next renewal ([`DnsCache::rearm_lapsed`]), or for serve-stale
    /// once the entry expires.
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

/// Keeps the cache renewed, bounded and clean: renewals, expiry, eviction and
/// bloom rotation all run on the worker [`Self::start_refresh_worker`] spawns.
pub struct DnsCacheMaintenance;

impl DnsCacheMaintenance {
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
                response_status: Some(resolution.rcode_name()),
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

    /// Spawns the worker that renews cache entries and removes them.
    ///
    /// It takes serve-stale repairs from `stale_rx`, always first, and the
    /// timers the cache arms as it stores, renews and parks entries. Each
    /// second it collects the timers armed since the last tick and takes
    /// those that came due: a renewal is claimed, a dead entry or an expired
    /// negative one removed. Up to `MAX_CONCURRENT_REFRESHES` renewals run at
    /// once; when more are due, hot ones (by `thresholds`) go first.
    ///
    /// The same tick evicts a cache that reached `cache_max_entries` and
    /// rotates the bloom filter on its period, each on a blocking thread.
    pub fn start_refresh_worker(
        cache: Arc<DnsCache>,
        resolver: Arc<dyn DnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        stale_rx: mpsc::Receiver<RefreshRequest>,
        thresholds: ColdThresholds,
    ) {
        let base_sweep_at = cache.max_entries().saturating_mul(SWEEP_FACTOR);
        // Rotation only bounds how long bits left behind by removed keys
        // linger: `rotate_bloom` re-seeds every live entry into the new slot,
        // so an entry's visibility does not depend on this cadence.
        let bloom_rotation_secs =
            (u64::from(cache.min_ttl()) / 60).max(MIN_BLOOM_ROTATION_MINUTES) * 60;
        info!(
            bloom_rotation_secs,
            "Bloom rotation throttled to every {} seconds", bloom_rotation_secs,
        );
        let timers = Arc::clone(cache.timer_inbox());
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
            bloom_rotation_secs,
            next_rotation_at_secs: coarse_clock::coarse_now_secs() + bloom_rotation_secs,
            evicting: None,
            rotating: None,
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
    /// The cache's timers, collected on the tick; arming a timer never wakes
    /// this task.
    timers: Arc<TimerInbox>,
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
    /// Where the sweep in progress resumes.
    sweep_from: Option<SweepFrom>,
    /// Seconds between bloom rotations.
    bloom_rotation_secs: u64,
    /// The second the next bloom rotation is due.
    next_rotation_at_secs: u64,
    /// The eviction pass last started, so a slow one is not stacked on.
    evicting: Option<JoinHandle<()>>,
    /// The bloom rotation last started.
    rotating: Option<JoinHandle<()>>,
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

                _ = tick.tick() => self.on_tick(),

                permit = Arc::clone(&self.permits).acquire_owned(), if has_work => {
                    let Ok(permit) = permit else { break };
                    self.start_next(permit);
                }
            }
        }
    }

    /// Registers every timer armed since the last tick.
    fn collect_timers(&mut self) {
        let schedule = &mut self.schedule;
        self.timers.drain(|timer| schedule.register(timer));
    }

    /// Everything the worker does once a second, besides starting work.
    fn on_tick(&mut self) {
        // In step with the clock the records are stamped with, so a timer
        // fires on its second, not up to a second after it.
        coarse_clock::tick();
        self.collect_timers();
        let now = coarse_clock::coarse_now_secs();
        self.fire_due(now);
        self.give_up_dead_claims(now);
        self.sweep_step();
        self.maintain(now);
    }

    /// Takes the timers that came due: a renewal is claimed, a dead entry or
    /// an expired negative one removed.
    fn fire_due(&mut self, now: u64) {
        for timer in self.schedule.take_due(now) {
            if timer.kind == TimerKind::NegativeExpiry {
                self.cache.expire_negative(&timer.key, now);
            } else if let Some(due) = self.cache.claim_due_refresh(&timer, now, &self.thresholds) {
                self.due.push(due);
            }
        }
    }

    /// Removes the claimed entries that died waiting for a permit. A claim
    /// holds no timer, so while hot renewals keep a cold one from its permit,
    /// nothing else would.
    fn give_up_dead_claims(&mut self, now: u64) {
        if self.due.is_empty() {
            return;
        }
        let cache = &self.cache;
        self.due.retain(|due| {
            if !due.has_died_by(now) {
                return true;
            }
            cache.give_up_dead_claim(&due.key, now);
            false
        });
    }

    /// Evicts a cache that reached `cache_max_entries` and rotates the bloom
    /// filter when its period comes round. Both are passes over the cache, so
    /// each runs on a blocking thread, one at a time, while this task carries
    /// on with renewals; a cache still full on the next tick is evicted again.
    fn maintain(&mut self, now: u64) {
        if self.cache.is_over_capacity() {
            Self::run_pass(&mut self.evicting, &self.cache, |cache| {
                cache.evict_entries()
            });
        }
        if now >= self.next_rotation_at_secs {
            self.next_rotation_at_secs = now + self.bloom_rotation_secs;
            Self::run_pass(&mut self.rotating, &self.cache, |cache| {
                cache.rotate_bloom();
            });
        }
    }

    /// Runs `pass` on a blocking thread, unless the one `last` started has
    /// not finished yet.
    fn run_pass(
        last: &mut Option<JoinHandle<()>>,
        cache: &Arc<DnsCache>,
        pass: impl FnOnce(&DnsCache) + Send + 'static,
    ) {
        if last.as_ref().is_some_and(|pass| !pass.is_finished()) {
            return;
        }
        let cache = Arc::clone(cache);
        *last = Some(tokio::task::spawn_blocking(move || pass(&cache)));
    }

    /// Drops a slice of the timers whose entry is gone. They would cost
    /// nothing when they fire, but under eviction churn they pile up for as
    /// long as the longest TTL.
    fn sweep_step(&mut self) {
        let from = match self.sweep_from {
            Some(from) => from,
            None if self.schedule.len() > self.sweep_at => SweepFrom::START,
            None => return,
        };
        let cache = &self.cache;
        self.sweep_from = self.schedule.sweep(from, SWEEP_BUDGET, |key, kind| {
            if kind == TimerKind::NegativeExpiry {
                cache.holds_negative(key)
            } else {
                cache.holds(key)
            }
        });
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
            // A claim the cache refuses leaves the entry with a timer or gone.
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
    /// its one more attempt here, if any, or else its next renewal a
    /// `cache_compaction_interval` away, armed before it lets go of the entry.
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
        match origin.retry_in(outcome, remaining) {
            Some(in_secs) => cache.schedule_retry(key, in_secs),
            None => cache.rearm_lapsed(key),
        }
        cache.reset_refreshing_of(key);
    }
}
