use super::bloom::AtomicBloom;
use super::coarse_clock::coarse_now_secs;
use super::eviction::{ActiveEvictionPolicy, EvictionStrategy};
use super::key::{normalize_domain, BorrowedKey, CacheKey};
use super::l1::{l1_clear, l1_get, l1_insert};
use super::negative_cache::NegativeDnsCache;
use super::port::{DnsCacheAccess, LocalRecordStatus};
use super::schedule::{ScheduledRefresh, TimerInbox};
use super::{CacheMetrics, CachedData, CachedDnssecStatus, CachedRecord};
use compact_str::CompactString;
use dashmap::mapref::one::RefMut;
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;
use std::collections::BinaryHeap;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc;
use tracing::{debug, info};

type PermanentTypes = SmallVec<[RecordType; 2]>;

struct EvictionCandidate {
    score: f64,
    key: CacheKey,
}

impl PartialEq for EvictionCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.score.total_cmp(&other.score) == std::cmp::Ordering::Equal
    }
}

impl Eq for EvictionCandidate {}

impl PartialOrd for EvictionCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvictionCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score.total_cmp(&other.score)
    }
}

const BLOOM_TARGET_FP_RATE: f64 = 0.01;
/// The TTL a stale hit reports (RFC 8767 §4).
pub(crate) const STALE_SERVE_TTL: u32 = 2;

/// Message carried by the serve-stale repair queue: the entry's name, type
/// and cache view.
pub type RefreshRequest = (Arc<str>, RecordType, u32);

/// What the cache hands the refresh worker, wired up by cache maintenance.
///
/// Separate because they are served differently: a serve-stale repair has a
/// client waiting on it and always goes first, while a timer only says when
/// an entry falls due.
pub struct RefreshSenders {
    /// Serve-stale repairs: a client already holds a stale answer and is
    /// waiting on the real one.
    pub stale: mpsc::Sender<RefreshRequest>,
    /// Refresh timers, armed as entries are stored and renewed. `None` when
    /// `cache_optimistic_refresh` is off: nothing is renewed ahead of expiry.
    pub timers: Option<Arc<TimerInbox>>,
}

pub struct DnsCacheConfig {
    pub max_entries: usize,
    pub eviction_strategy: EvictionStrategy,
    pub refresh_threshold: f64,
    pub batch_eviction_percentage: f64,
    pub min_frequency: u64,
    pub min_lfuk_score: f64,
    pub shard_amount: usize,
    pub access_window_secs: u64,
    pub eviction_sample_size: usize,
    pub lfuk_k_value: f64,
    pub min_ttl: u32,
    pub max_ttl: u32,
}

pub struct DnsCache {
    pub(super) cache: DashMap<CacheKey, CachedRecord, FxBuildHasher>,
    pub(super) max_entries: usize,
    pub(super) eviction_policy: ActiveEvictionPolicy,
    pub(super) refresh_threshold: f64,
    pub(super) batch_eviction_percentage: f64,
    pub(super) metrics: CacheMetrics,
    pub(super) bloom: AtomicBloom,
    pub(super) access_window_secs: u64,
    pub(super) eviction_sample_size: usize,
    pub(super) negative: NegativeDnsCache,
    permanent_records: DashMap<CompactString, PermanentTypes, FxBuildHasher>,
    min_ttl: u32,
    max_ttl: u32,
    refresh_senders: OnceLock<RefreshSenders>,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        let eviction_policy = ActiveEvictionPolicy::from_config(
            config.eviction_strategy,
            config.min_frequency,
            config.min_lfuk_score,
            config.lfuk_k_value,
        );

        info!(
            max_entries = config.max_entries,
            eviction_strategy = config.eviction_strategy.as_str(),
            config.refresh_threshold,
            "Initializing DNS cache"
        );

        let cache = DashMap::with_capacity_and_hasher_and_shard_amount(
            config.max_entries,
            FxBuildHasher,
            config.shard_amount,
        );
        let bloom = AtomicBloom::new(config.max_entries * 2, BLOOM_TARGET_FP_RATE);

        Self {
            cache,
            max_entries: config.max_entries,
            eviction_policy,
            refresh_threshold: config.refresh_threshold,
            batch_eviction_percentage: config.batch_eviction_percentage,
            metrics: CacheMetrics::default(),
            bloom,
            access_window_secs: config.access_window_secs,
            eviction_sample_size: config.eviction_sample_size.max(1),
            negative: NegativeDnsCache::new(config.max_entries),
            permanent_records: DashMap::with_hasher(FxBuildHasher),
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            refresh_senders: OnceLock::new(),
        }
    }

    #[inline(always)]
    pub(crate) fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.clamp(self.min_ttl, self.max_ttl)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Locks every shard in turn, so it belongs on the maintenance cycle, never
    /// on a per-query path.
    pub(crate) fn is_over_capacity(&self) -> bool {
        self.cache.len() >= self.max_entries
    }

    /// A hit's data, DNSSEC status, remaining TTL, and whether the local DNS
    /// server gave the answer.
    #[inline]
    pub fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>, bool)> {
        self.get_in(domain, record_type, 0)
    }

    /// [`Self::get`] in cache view `view`: 0 for the view every client
    /// shares, else the group whose split-horizon answers it holds.
    pub fn get_in(
        &self,
        domain: &str,
        record_type: &RecordType,
        view: u32,
    ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>, bool)> {
        let domain = normalize_domain(domain);
        let domain = domain.as_ref();

        // Hits leave the bloom alone: `rotate_bloom` re-seeds every live key,
        // so reads never decide membership. L1 mirrors L2's address answers,
        // so only an A or AAAA probe is worth its lookup. L1 is keyed by name
        // alone, so it only ever holds the shared view.
        if view == 0 && matches!(record_type, RecordType::A | RecordType::AAAA) {
            if let Some((arc_data, dnssec_status, local_dns, remaining_ttl, l1_hits)) =
                l1_get(domain, record_type)
            {
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                if l1_hits > 0 {
                    self.record_l1_hits(domain, *record_type, l1_hits);
                }
                return Some((
                    CachedData::IpAddresses(super::data::CachedAddresses {
                        addresses: arc_data,
                    }),
                    Some(dnssec_status),
                    Some(remaining_ttl),
                    local_dns,
                ));
            }
        }

        let borrowed = BorrowedKey::new(domain, *record_type).in_view(view);
        let in_bloom = self.bloom.check(&borrowed);

        if !in_bloom {
            if let Some((remaining_ttl, local_dns)) = self.negative.get(domain, record_type, view) {
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                return Some((
                    CachedData::NegativeResponse,
                    None,
                    Some(remaining_ttl),
                    local_dns,
                ));
            }
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }

        let key = CacheKey::from_lowercase(domain, *record_type).in_view(view);

        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();

            let now_secs = coarse_now_secs();

            if record.is_stale_usable_at_secs(now_secs) {
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                self.metrics
                    .stale_hits
                    .fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                if let Some(senders) = self.refresh_senders.get() {
                    if record.try_set_refreshing()
                        && senders
                            .stale
                            .try_send((Arc::from(domain), key.record_type, view))
                            .is_err()
                    {
                        record.clear_refreshing();
                        self.metrics
                            .stale_refresh_drops
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
                return Some((
                    record.data.clone(),
                    Some(record.dnssec_status),
                    Some(STALE_SERVE_TTL),
                    record.is_local_dns(),
                ));
            }

            if record.is_expired_at_secs(now_secs) {
                record.mark_for_deletion();
                self.metrics
                    .lazy_deletions
                    .fetch_add(1, AtomicOrdering::Relaxed);
                drop(entry);
            } else {
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                if record.is_refresh_parked() {
                    self.rearm_refresh(&key, record);
                }
                let remaining_ttl = record.remaining_ttl_at_secs(now_secs);
                if view == 0 {
                    self.promote_to_l1(domain, record_type, record, now_secs);
                }
                return Some((
                    record.data.clone(),
                    Some(record.dnssec_status),
                    Some(remaining_ttl),
                    record.is_local_dns(),
                ));
            }
        }

        if let Some((remaining_ttl, local_dns)) = self.negative.get(domain, record_type, view) {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((
                CachedData::NegativeResponse,
                None,
                Some(remaining_ttl),
                local_dns,
            ));
        }

        self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
        None
    }

    /// Caches an upstream answer; [`DnsCacheAccess::insert`] also caches local ones.
    pub fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<CachedDnssecStatus>,
    ) {
        let domain = normalize_domain(domain);
        let key = BorrowedKey::new(domain.as_ref(), record_type);
        self.store(key, data, ttl, dnssec_status, false);
    }

    /// Stores under `key`, whose view says which clients it answers.
    /// `local_dns` marks an answer from the local DNS server, which its hits report.
    fn store(
        &self,
        key: BorrowedKey<'_>,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<CachedDnssecStatus>,
        local_dns: bool,
    ) {
        let BorrowedKey {
            domain,
            record_type,
            view,
        } = key;

        if data.is_negative() {
            // Negative cache enforces its own `[MIN_NEGATIVE_TTL, MAX_NEGATIVE_TTL]`
            // window. Do NOT apply
            // `clamp_ttl` here: the general `cache_min_ttl`/`cache_max_ttl` from
            // config is meant for positive records; inflating positives would
            // break the refresh/access-window cycle, while deflating negatives
            // would defeat the 300s floor that keeps NXDOMAINs from escaping
            // to upstream on every repeated miss.
            self.negative
                .insert(domain, record_type, ttl, local_dns, view);
            return;
        }

        let ttl = self.clamp_ttl(ttl);
        let Some(data) = data.into_stored(ttl, self.min_ttl..=self.max_ttl) else {
            debug!(domain = %domain, record_type = %record_type, "Answer does not re-section; not cached");
            return;
        };
        let key = CacheKey::from_lowercase(domain, record_type).in_view(view);
        let maybe_l1_addresses = data.as_ip_addresses().filter(|_| view == 0).cloned();

        let record = CachedRecord::new(data, ttl, record_type, dnssec_status);
        let mut record = if local_dns {
            record.with_local_dns()
        } else {
            record
        };
        let expires_secs = record.expires_at_secs;
        // Armed before it is visible, so nothing else can arm it as well.
        let timer = self.arming_inbox(ttl).map(|inbox| {
            let due_at_secs = record.refresh_due_at_secs(self.refresh_threshold);
            record.set_refresh_timer(due_at_secs);
            let timer = ScheduledRefresh {
                due_at_secs,
                key: key.clone(),
                retry: false,
            };
            (inbox, timer)
        });

        self.bloom.set(&key);
        match self.cache.entry(key) {
            dashmap::Entry::Vacant(e) => {
                e.insert(record);
                self.metrics
                    .insertions
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
            // A local record is configuration: an upstream answer that raced
            // its creation must not replace it, here or in L1.
            dashmap::Entry::Occupied(e) if e.get().is_permanent() => return,
            dashmap::Entry::Occupied(mut e) => {
                e.insert(record);
            }
        }

        if let Some((inbox, timer)) = timer {
            self.push_or_release(inbox, timer);
        }

        if let Some(addresses) = maybe_l1_addresses {
            // The hits the replaced copy batched belonged to the replaced
            // record, whose counters this one does not carry over.
            l1_insert(
                domain,
                &record_type,
                addresses,
                dnssec_status.unwrap_or(CachedDnssecStatus::Unknown),
                local_dns,
                expires_secs,
            );
        }

        debug!(
            domain = %domain,
            record_type = %record_type,
            ttl,
            "Inserted record into cache"
        );
    }

    pub fn insert_permanent(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
    ) {
        let domain = normalize_domain(domain);
        let domain = domain.as_ref();
        // A local record reports its configured TTL, so its records keep theirs.
        let Some(data) = data.into_stored(ttl, 0..=u32::MAX) else {
            return;
        };
        let key = CacheKey::from_lowercase(domain, record_type);
        self.bloom.set(&key);

        if self.cache.len() >= self.max_entries {
            self.evict_entries();
        }

        let maybe_l1_addresses = data.as_ip_addresses().cloned();
        let record = CachedRecord::permanent(data, ttl, record_type);
        let _owner = self.claim_permanent(&key.domain, record_type);
        self.cache.insert(key, record);

        if let Some(addresses) = maybe_l1_addresses {
            // Permanent (local DNS / hosts) entries are not DNSSEC-validated.
            // L1 gets a real expiry so the TTL it reports is the configured one;
            // when it lapses the entry is simply promoted again from L2, which
            // still holds it forever.
            l1_insert(
                domain,
                &record_type,
                addresses,
                CachedDnssecStatus::Unknown,
                false,
                coarse_now_secs() + ttl as u64,
            );
        }
    }

    /// Whether `domain`/`record_type` is held as a permanent entry — a local DNS
    /// record preloaded from config, not something resolved from upstream.
    pub fn is_permanent(&self, domain: &str, record_type: &RecordType) -> bool {
        let domain = normalize_domain(domain);
        self.permanent_records
            .get(domain.as_ref())
            .is_some_and(|types| types.contains(record_type))
    }

    pub fn remove(&self, domain: &str, record_type: &RecordType) -> bool {
        let domain = normalize_domain(domain);
        let domain = domain.as_ref();
        let key = CacheKey::from_lowercase(domain, *record_type);

        let permanent_entry = self.permanent_records.entry(key.domain.clone());
        if self.cache.remove(&key).is_some() {
            if let dashmap::Entry::Occupied(mut entry) = permanent_entry {
                entry.get_mut().retain(|kind| *kind != *record_type);
                if entry.get().is_empty() {
                    entry.remove();
                }
            }
            self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
            // The per-thread L1 keeps serving a removed record until it
            // expires locally, so bump the generation like `clear()` does.
            l1_clear();
            info!(domain = %domain, record_type = %record_type, "Removed record from cache");
            true
        } else {
            false
        }
    }

    /// [`Self::remove`] in cache view `view`. A group's view never holds a
    /// local record nor an L1 copy, so only its own entry goes.
    pub fn remove_in(&self, domain: &str, record_type: &RecordType, view: u32) -> bool {
        if view == 0 {
            return self.remove(domain, record_type);
        }
        let key = CacheKey::new(domain, *record_type).in_view(view);
        if self.cache.remove(&key).is_none() {
            return false;
        }
        self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
        info!(domain = %key.domain, record_type = %record_type, view, "Removed record from cache");
        true
    }

    pub fn clear(&self) {
        // Permanent entries are configuration, not cached upstream answers:
        // local DNS records live here and nothing reloads them, so dropping them
        // would leave every one of them unanswerable until the next restart.
        let mut preserved = Vec::new();
        for types in self.permanent_records.iter() {
            for &record_type in types.value() {
                let key = CacheKey {
                    domain: types.key().clone(),
                    record_type,
                    view: 0,
                };
                if let Some(record) = self.cache.get(&key) {
                    preserved.push((key, record.data.clone(), record.ttl));
                }
            }
        }

        self.cache.clear();
        self.bloom.clear();
        self.negative.clear();
        self.permanent_records.clear();
        l1_clear();
        self.metrics.hits.store(0, AtomicOrdering::Relaxed);
        self.metrics.misses.store(0, AtomicOrdering::Relaxed);
        self.metrics.evictions.store(0, AtomicOrdering::Relaxed);

        let restored = preserved.len();
        for (key, data, ttl) in preserved {
            self.bloom.set(&key);
            let _owner = self.claim_permanent(&key.domain, key.record_type);
            let record = CachedRecord::permanent(data, ttl, key.record_type);
            self.cache.insert(key, record);
        }

        info!(
            restored,
            "Cache cleared (L1 generation bumped for cross-thread invalidation)"
        );
    }

    /// Registers `record_type` as permanent at `domain` and keeps the name's
    /// entry locked: callers write the backing map under it, as `remove` does,
    /// so a concurrent removal cannot discard a newly inserted name or family.
    fn claim_permanent(
        &self,
        domain: &CompactString,
        record_type: RecordType,
    ) -> RefMut<'_, CompactString, PermanentTypes> {
        let mut types = self.permanent_records.entry(domain.clone()).or_default();
        if !types.contains(&record_type) {
            types.push(record_type);
        }
        types
    }

    pub fn metrics(&self) -> &CacheMetrics {
        &self.metrics
    }

    pub fn get_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new(domain, *record_type);
        self.cache.get(&key).map(|entry| entry.ttl)
    }

    pub fn get_remaining_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        self.remaining_ttl_of(&CacheKey::new(domain, *record_type))
    }

    pub(crate) fn remaining_ttl_of(&self, key: &CacheKey) -> Option<u32> {
        self.cache
            .get(key)
            .map(|entry| entry.remaining_ttl_at_secs(coarse_now_secs()))
    }

    /// Rotates the two-slot aging bloom and re-seeds it from the live cache.
    ///
    /// The filter is an authoritative negative gate in [`Self::get`]: a key
    /// whose bits are absent is reported as a miss without consulting the map,
    /// and reads never set bits. Re-seeding every live entry ties membership to
    /// what the cache holds, so an entry nobody wrote to for two rotations
    /// stays reachable for as long as its TTL allows.
    ///
    /// Returns how many keys were re-seeded into the new active slot.
    pub fn rotate_bloom(&self) -> usize {
        self.bloom.rotate();

        let now = coarse_now_secs();
        let mut reseeded = 0usize;

        for entry in self.cache.iter() {
            let record = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }
            if record.is_expired_at_secs(now) && !record.is_stale_usable_at_secs(now) {
                continue;
            }
            self.bloom.set(entry.key());
            reseeded += 1;
        }

        for types in self.permanent_records.iter() {
            for &record_type in types.value() {
                self.bloom
                    .set(&BorrowedKey::new(types.key().as_str(), record_type));
            }
        }

        debug!(reseeded, "Bloom rotated and re-seeded from live cache");
        reseeded
    }

    pub fn min_ttl(&self) -> u32 {
        self.min_ttl
    }

    pub fn set_refresh_senders(&self, senders: RefreshSenders) {
        if self.refresh_senders.set(senders).is_err() {
            tracing::warn!("Refresh senders already configured — second pair dropped");
        }
    }

    /// Where refresh timers go, while optimistic refresh is on and its worker
    /// is wired up.
    #[inline]
    pub(super) fn timer_inbox(&self) -> Option<&Arc<TimerInbox>> {
        self.refresh_senders
            .get()
            .and_then(|senders| senders.timers.as_ref())
    }

    /// [`Self::timer_inbox`] for an entry of `ttl`: one that expires at once
    /// is never renewed ahead of expiry.
    #[inline]
    fn arming_inbox(&self, ttl: u32) -> Option<&Arc<TimerInbox>> {
        if ttl == 0 {
            return None;
        }
        self.timer_inbox()
    }

    /// Hands `timer` to the worker. A full inbox gives it back, counted as
    /// shed; the caller then lapses the entry, so compaction arms it again.
    #[inline]
    fn push_refresh_timer(
        &self,
        inbox: &TimerInbox,
        timer: ScheduledRefresh,
    ) -> Result<(), ScheduledRefresh> {
        inbox.push(timer).inspect_err(|_| {
            self.metrics
                .optimistic_refresh_shed
                .fetch_add(1, AtomicOrdering::Relaxed);
        })
    }

    /// [`Self::push_refresh_timer`] for a caller holding no guard on the
    /// entry, which is looked up again to lapse it if the inbox is full.
    pub(super) fn push_or_release(&self, inbox: &TimerInbox, timer: ScheduledRefresh) {
        if let Err(timer) = self.push_refresh_timer(inbox, timer) {
            if let Some(entry) = self.cache.get(&timer.key) {
                entry.release_refresh_timer(timer.due_at_secs);
            }
        }
    }

    /// Arms a parked entry that is in use again, for the second it falls due
    /// (often already past, so it fires on the next tick). The caller holds
    /// the entry, which is why it is passed in rather than looked up.
    #[cold]
    fn rearm_refresh(&self, key: &CacheKey, record: &CachedRecord) {
        let Some(inbox) = self.arming_inbox(record.ttl) else {
            return;
        };
        let due_at_secs = record.refresh_due_at_secs(self.refresh_threshold);
        if !record.try_unpark_refresh(due_at_secs) {
            return;
        }
        let timer = ScheduledRefresh {
            due_at_secs,
            key: key.clone(),
            retry: false,
        };
        if self.push_refresh_timer(inbox, timer).is_err() {
            record.release_refresh_timer(due_at_secs);
        }
    }

    /// Arms the one more attempt a renewal on a timer gets when it did not
    /// renew the entry, `in_secs` from now. Called while that renewal still
    /// holds the entry, so compaction cannot arm it first; a renewal or a
    /// re-arm that won the entry in the meantime keeps its own timer.
    pub(crate) fn schedule_retry(&self, key: &CacheKey, in_secs: u64) {
        let Some(inbox) = self.timer_inbox() else {
            return;
        };
        let due_at_secs = coarse_now_secs() + in_secs;
        let armed = self
            .cache
            .get(key)
            .is_some_and(|entry| entry.try_rearm_lapsed_refresh(due_at_secs));
        if armed {
            let timer = ScheduledRefresh {
                due_at_secs,
                key: key.clone(),
                retry: true,
            };
            self.push_or_release(inbox, timer);
        }
    }

    /// Whether `key` is cached. For the worker's sweep of timers whose entry
    /// is gone.
    pub(crate) fn holds(&self, key: &CacheKey) -> bool {
        self.cache.contains_key(key)
    }

    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn refresh_record(
        &self,
        domain: &str,
        record_type: &RecordType,
        new_ttl: Option<u32>,
        new_data: CachedData,
        dnssec_status: Option<CachedDnssecStatus>,
    ) -> bool {
        let domain = normalize_domain(domain);
        let key = CacheKey::from_lowercase(domain.as_ref(), *record_type);
        self.refresh_record_of(&key, new_ttl, new_data, dnssec_status)
    }

    /// [`Self::refresh_record`] for `key`, in whatever view it names.
    pub(crate) fn refresh_record_of(
        &self,
        key: &CacheKey,
        new_ttl: Option<u32>,
        new_data: CachedData,
        dnssec_status: Option<CachedDnssecStatus>,
    ) -> bool {
        let domain = key.domain.as_str();
        let record_type = &key.record_type;
        let Some(ttl) = new_ttl.or_else(|| self.cache.get(key).map(|entry| entry.ttl)) else {
            return false;
        };
        let ttl = self.clamp_ttl(ttl);
        let Some(new_data) = new_data.into_stored(ttl, self.min_ttl..=self.max_ttl) else {
            return false;
        };
        let now = coarse_now_secs();
        let timer = if let Some(mut entry) = self.cache.get_mut(key) {
            let record = entry.value_mut();
            if record.is_permanent() || record.is_marked_for_deletion() {
                return false;
            }
            // The new data counts its records' age from this `ttl` and instant.
            record.expires_at_secs = now + ttl as u64;
            record.inserted_at_secs = now;
            record.ttl = ttl;
            if let Some(ds) = dnssec_status {
                record.dnssec_status = ds;
            }
            // The rate window and the flags all key off this renewal, so they
            // move together with `inserted_at_secs` above.
            record.note_refreshed();
            record.clear_refreshing();

            let maybe_l1_addresses = new_data
                .as_ip_addresses()
                .filter(|_| key.view == 0)
                .cloned();
            record.data = new_data;

            if let Some(addresses) = maybe_l1_addresses {
                let batched = l1_insert(
                    domain,
                    record_type,
                    addresses,
                    record.dnssec_status,
                    record.is_local_dns(),
                    record.expires_at_secs,
                );
                if batched > 0 {
                    record.record_hits(u64::from(batched));
                }
            }

            // A renewed TTL is worthless if the bloom gate no longer admits the
            // key, so re-arm it here too instead of waiting for the next rotation.
            self.bloom.set(key);

            // The new lifetime gets its own timer, which replaces whatever the
            // entry had pending: that one now fires stale.
            match self.arming_inbox(ttl) {
                Some(inbox) => {
                    let due_at_secs = record.refresh_due_at_secs(self.refresh_threshold);
                    record.set_refresh_timer(due_at_secs);
                    let timer = ScheduledRefresh {
                        due_at_secs,
                        key: key.clone(),
                        retry: false,
                    };
                    Some((inbox, timer))
                }
                None => {
                    record.lapse_refresh_timer();
                    None
                }
            }
        } else {
            return false;
        };

        if let Some((inbox, timer)) = timer {
            self.push_or_release(inbox, timer);
        }
        true
    }

    /// Hands a batch of hits an L1 copy served over to its L2 record, which
    /// holds the counters refresh eligibility and eviction read. Runs at most
    /// once per second per thread and name; a record gone in the meantime
    /// just drops the batch.
    fn record_l1_hits(&self, domain: &str, record_type: RecordType, hits: u16) {
        let key = CacheKey::from_lowercase(domain, record_type);
        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();
            record.record_hits(u64::from(hits));
            if record.is_refresh_parked() {
                self.rearm_refresh(&key, record);
            }
        }
    }

    /// L1 thread-local cache only holds IP addresses (A/AAAA).
    /// WireData, CanonicalName, and NegativeResponse stay in L2 only.
    fn promote_to_l1(
        &self,
        domain: &str,
        record_type: &RecordType,
        record: &CachedRecord,
        now_secs: u64,
    ) {
        if let CachedData::IpAddresses(entry) = &record.data {
            if record.expires_at_secs <= now_secs {
                return;
            }
            // Same reason as in `get`: a permanent entry's `expires_at_secs` is
            // u64::MAX, which L1 would turn into an absurd remaining TTL.
            let expires_secs = if record.is_permanent() {
                now_secs + record.ttl as u64
            } else {
                record.expires_at_secs
            };
            let batched = l1_insert(
                domain,
                record_type,
                Arc::clone(&entry.addresses),
                record.dnssec_status,
                record.is_local_dns(),
                expires_secs,
            );
            if batched > 0 {
                record.record_hits(u64::from(batched));
            }
        }
    }

    /// Removes up to `count` entries without scoring them — the cheap path for
    /// a cache that already sits below half its capacity.
    ///
    /// The keys are collected into a `Vec` that **ends the statement**: a
    /// dashmap `Iter` holds the read guard of the shard it is walking, and
    /// `remove` needs the write guard of that same shard. `parking_lot`'s
    /// `RawRwLock` is not reentrant, so removing while the iterator is alive
    /// deadlocks the thread for good (issue #228).
    ///
    /// Permanent entries are skipped for the same reason [`Self::evict_by_strategy`]
    /// skips them: they are local DNS records loaded from config, nothing
    /// reloads them, and dropping one here would leave `permanent_records`
    /// claiming a name the backing map no longer holds.
    fn evict_arbitrary_entries(&self, count: usize) {
        let keys: Vec<CacheKey> = self
            .cache
            .iter()
            .filter(|entry| {
                let record = entry.value();
                !record.is_permanent() && !record.is_marked_for_deletion()
            })
            .map(|entry| entry.key().clone())
            .take(count)
            .collect();

        let mut evicted = 0u64;
        for key in &keys {
            if self.cache.remove(key).is_some() {
                evicted += 1;
            }
        }

        if evicted > 0 {
            self.metrics
                .evictions
                .fetch_add(evicted, AtomicOrdering::Relaxed);
        }
    }

    pub fn evict_entries(&self) {
        let num_to_evict = ((self.max_entries as f64) * self.batch_eviction_percentage) as usize;
        let num_to_evict = num_to_evict.max(1);

        if self.cache.len() > self.max_entries / 2 {
            self.evict_by_strategy(num_to_evict);
        } else {
            self.evict_arbitrary_entries(num_to_evict);
        }
    }

    fn evict_by_strategy(&self, count: usize) {
        if self.cache.is_empty() {
            return;
        }

        let now_secs = coarse_now_secs();
        let total_to_sample = count * self.eviction_sample_size;

        struct RecordSnapshot {
            key: CacheKey,
            hit_count: u64,
            last_access: u64,
            inserted_at: u64,
            is_expired: bool,
        }

        let mut snapshots = Vec::with_capacity(total_to_sample);
        let mut sampled = 0usize;

        for entry in self.cache.iter() {
            if sampled >= total_to_sample {
                break;
            }
            let record = entry.value();
            if record.is_marked_for_deletion() || record.is_permanent() {
                continue;
            }
            snapshots.push(RecordSnapshot {
                key: entry.key().clone(),
                hit_count: record.counters.hit_count.load(AtomicOrdering::Relaxed),
                last_access: record.counters.last_access.load(AtomicOrdering::Relaxed),
                inserted_at: record.inserted_at_secs,
                is_expired: record.is_expired_at_secs(now_secs),
            });
            sampled += 1;
        }

        let mut heap: BinaryHeap<EvictionCandidate> = BinaryHeap::with_capacity(count + 1);
        let mut urgent_keys: Vec<CacheKey> = Vec::new();

        for snap in &snapshots {
            if snap.is_expired {
                let within_window =
                    now_secs.saturating_sub(snap.last_access) <= self.access_window_secs;

                if !within_window {
                    urgent_keys.push(snap.key.clone());
                    continue;
                }
            }

            let score = self.eviction_policy.score(
                snap.hit_count,
                snap.last_access,
                snap.inserted_at,
                now_secs,
            );
            let candidate = EvictionCandidate {
                score,
                key: snap.key.clone(),
            };
            if heap.len() < count {
                heap.push(candidate);
            } else if let Some(top) = heap.peek() {
                if score < top.score {
                    heap.pop();
                    heap.push(candidate);
                }
            }
        }

        for key in &urgent_keys {
            if let Some(entry) = self.cache.get(key) {
                entry.value().mark_for_deletion();
            }
        }

        let evict_count = count.saturating_sub(urgent_keys.len());
        let mut candidates: Vec<EvictionCandidate> = heap.into_vec();
        candidates.sort_unstable_by(|a, b| a.score.total_cmp(&b.score));

        let mut scored_evicted = 0usize;
        for candidate in candidates.into_iter().take(evict_count) {
            self.cache.remove(&candidate.key);
            scored_evicted += 1;
        }

        let retain_removed = if !urgent_keys.is_empty() {
            let before = self.cache.len();
            self.cache
                .retain(|_, record| !record.is_marked_for_deletion());
            before.saturating_sub(self.cache.len())
        } else {
            0
        };

        let total_evicted = (scored_evicted + retain_removed) as u64;
        self.metrics
            .evictions
            .fetch_add(total_evicted, AtomicOrdering::Relaxed);
        self.metrics
            .batch_evictions
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
}

impl ferrous_dns_application::ports::DnsCachePort for DnsCache {
    fn cache_size(&self) -> usize {
        self.len()
    }

    fn cache_metrics_snapshot(&self) -> ferrous_dns_application::ports::CacheMetricsSnapshot {
        let metrics = &self.metrics;
        let hits = metrics.hits.load(AtomicOrdering::Relaxed);
        let misses = metrics.misses.load(AtomicOrdering::Relaxed);
        ferrous_dns_application::ports::CacheMetricsSnapshot {
            total_entries: self.len(),
            hits,
            misses,
            insertions: metrics.insertions.load(AtomicOrdering::Relaxed),
            evictions: metrics.evictions.load(AtomicOrdering::Relaxed),
            optimistic_refreshes: metrics.optimistic_refreshes.load(AtomicOrdering::Relaxed),
            stale_hits: metrics.stale_hits.load(AtomicOrdering::Relaxed),
            lazy_deletions: metrics.lazy_deletions.load(AtomicOrdering::Relaxed),
            compactions: metrics.compactions.load(AtomicOrdering::Relaxed),
            batch_evictions: metrics.batch_evictions.load(AtomicOrdering::Relaxed),
            hit_rate: metrics.hit_rate(),
            transient_upstream_errors: metrics
                .transient_upstream_errors
                .load(AtomicOrdering::Relaxed),
            stale_refresh_drops: metrics.stale_refresh_drops.load(AtomicOrdering::Relaxed),
            optimistic_refresh_shed: metrics
                .optimistic_refresh_shed
                .load(AtomicOrdering::Relaxed),
        }
    }

    fn insert_permanent_record(
        &self,
        domain: &str,
        record_type: ferrous_dns_domain::RecordType,
        addresses: Vec<std::net::IpAddr>,
        ttl: u32,
    ) {
        let data = CachedData::IpAddresses(super::data::CachedAddresses {
            addresses: Arc::new(addresses),
        });
        self.insert_permanent(domain, record_type, data, ttl);
    }

    fn remove_record(
        &self,
        domain: &str,
        record_type: &ferrous_dns_domain::RecordType,
        group_id: Option<i64>,
    ) -> bool {
        match group_id {
            None => self.remove(domain, record_type),
            Some(id) => u32::try_from(id)
                .ok()
                .filter(|view| *view != 0)
                .is_some_and(|view| self.remove_in(domain, record_type, view)),
        }
    }

    fn is_permanent_record(
        &self,
        domain: &str,
        record_type: &ferrous_dns_domain::RecordType,
    ) -> bool {
        self.is_permanent(domain, record_type)
    }

    fn list_entries(
        &self,
        query: &ferrous_dns_application::ports::CacheEntryQuery,
    ) -> ferrous_dns_application::ports::CacheEntryPage {
        DnsCache::list_entries(self, query)
    }
}

impl DnsCacheAccess for DnsCache {
    fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
        view: u32,
    ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>, bool)> {
        DnsCache::get_in(self, domain, record_type, view)
    }

    fn local_record_status(&self, domain: &str, record_type: &RecordType) -> LocalRecordStatus {
        let domain = normalize_domain(domain);
        let Some(types) = self.permanent_records.get(domain.as_ref()) else {
            return LocalRecordStatus::NotLocal;
        };
        if types.contains(record_type) {
            LocalRecordStatus::Present
        } else if types
            .iter()
            .any(|kind| matches!(kind, RecordType::A | RecordType::AAAA))
        {
            LocalRecordStatus::MissingType
        } else {
            LocalRecordStatus::NotLocal
        }
    }

    fn insert(
        &self,
        key: BorrowedKey<'_>,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<CachedDnssecStatus>,
        local_dns: bool,
    ) {
        self.store(key, data, ttl, dnssec_status, local_dns);
    }

    fn record_transient_upstream_error(&self) {
        self.metrics
            .transient_upstream_errors
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
}
