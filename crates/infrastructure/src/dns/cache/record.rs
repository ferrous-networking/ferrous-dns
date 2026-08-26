use super::coarse_clock::coarse_now_secs;
use super::data::{CachedData, CachedDnssecStatus};
use ferrous_dns_domain::RecordType;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering as AtomicOrdering};

const FLAG_DELETED: u8 = 0b001;
const FLAG_REFRESHING: u8 = 0b010;
const FLAG_PERMANENT: u8 = 0b100;
/// Set when a maintenance cycle has handed the entry to the optimistic queue
/// but no resolution has started yet.
///
/// Deliberately distinct from `FLAG_REFRESHING`: an entry can sit queued for a
/// large part of a cycle, and during that window a client hitting the stale
/// path must still be able to schedule the fast, unpaced repair. Only
/// `FLAG_REFRESHING` — a resolution actually in flight — blocks that.
const FLAG_REFRESH_QUEUED: u8 = 0b1000;
const STALE_GRACE_PERIOD_MULTIPLIER: u64 = 2;

#[repr(align(64))]
pub struct HotCounters {
    pub hit_count: AtomicU64,
    pub last_access: AtomicU64,
    /// `hit_count` as of the last successful renewal.
    ///
    /// `refresh_record` resets `inserted_at_secs` but deliberately not
    /// `hit_count`, which the eviction policies read as a lifetime total. So a
    /// rate measured as `hit_count / age` would jump every renewal. Keeping the
    /// value at the last renewal is what makes "hits per minute since the last
    /// renewal" measurable.
    pub hits_at_last_refresh: AtomicU64,
}

impl HotCounters {
    fn new(now_secs: u64) -> Self {
        Self {
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_secs),
            hits_at_last_refresh: AtomicU64::new(0),
        }
    }
}

impl std::fmt::Debug for HotCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotCounters")
            .field("hit_count", &self.hit_count.load(AtomicOrdering::Relaxed))
            .field(
                "last_access",
                &self.last_access.load(AtomicOrdering::Relaxed),
            )
            .field(
                "hits_at_last_refresh",
                &self.hits_at_last_refresh.load(AtomicOrdering::Relaxed),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct CachedRecord {
    pub data: CachedData,
    pub dnssec_status: CachedDnssecStatus,
    pub expires_at_secs: u64,
    pub inserted_at_secs: u64,
    pub counters: HotCounters,
    pub ttl: u32,
    pub record_type: RecordType,
    pub flags: AtomicU8,
}

impl Clone for CachedRecord {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            dnssec_status: self.dnssec_status,
            expires_at_secs: self.expires_at_secs,
            inserted_at_secs: self.inserted_at_secs,
            counters: HotCounters {
                hit_count: AtomicU64::new(self.counters.hit_count.load(AtomicOrdering::Relaxed)),
                last_access: AtomicU64::new(
                    self.counters.last_access.load(AtomicOrdering::Relaxed),
                ),
                hits_at_last_refresh: AtomicU64::new(
                    self.counters
                        .hits_at_last_refresh
                        .load(AtomicOrdering::Relaxed),
                ),
            },
            ttl: self.ttl,
            record_type: self.record_type,
            flags: AtomicU8::new(self.flags.load(AtomicOrdering::Relaxed)),
        }
    }
}

impl CachedRecord {
    pub fn new(
        data: CachedData,
        ttl: u32,
        record_type: RecordType,
        dnssec_status: Option<CachedDnssecStatus>,
    ) -> Self {
        let now_secs = coarse_now_secs();

        Self {
            data,
            dnssec_status: dnssec_status.unwrap_or(CachedDnssecStatus::Unknown),
            expires_at_secs: now_secs + ttl as u64,
            inserted_at_secs: now_secs,
            counters: HotCounters::new(now_secs),
            ttl,
            record_type,
            flags: AtomicU8::new(0),
        }
    }

    pub fn permanent(data: CachedData, ttl: u32, record_type: RecordType) -> Self {
        let now_secs = coarse_now_secs();

        Self {
            data,
            dnssec_status: CachedDnssecStatus::Unknown,
            expires_at_secs: u64::MAX,
            inserted_at_secs: now_secs,
            counters: HotCounters::new(now_secs),
            ttl,
            record_type,
            flags: AtomicU8::new(FLAG_PERMANENT),
        }
    }

    #[inline(always)]
    pub fn is_permanent(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & FLAG_PERMANENT != 0
    }

    #[inline(always)]
    pub fn is_expired(&self) -> bool {
        if self.is_permanent() {
            return false;
        }
        coarse_now_secs() >= self.expires_at_secs
    }

    #[inline(always)]
    pub fn is_expired_at_secs(&self, now_secs: u64) -> bool {
        if self.is_permanent() {
            return false;
        }
        now_secs >= self.expires_at_secs
    }

    #[inline(always)]
    pub fn is_stale_usable_at_secs(&self, now_secs: u64) -> bool {
        let age = now_secs.saturating_sub(self.inserted_at_secs);
        let max_stale_age = (self.ttl as u64) * STALE_GRACE_PERIOD_MULTIPLIER;

        now_secs >= self.expires_at_secs && age < max_stale_age
    }

    /// The instant past which the entry stops being usable at all.
    ///
    /// Serving stale keeps an expired entry alive for `STALE_GRACE_PERIOD_MULTIPLIER`
    /// TTLs from insertion, so this is `expires_at + ttl`. It is the right
    /// ordering key for a refresh queue: unlike `expires_at_secs` alone it
    /// accounts for the TTL, so a 60-second entry about to expire correctly
    /// outranks an hour-long one about to expire.
    #[inline(always)]
    pub fn refresh_deadline_secs(&self) -> u64 {
        self.expires_at_secs
            .saturating_add((self.ttl as u64) * (STALE_GRACE_PERIOD_MULTIPLIER - 1))
    }

    pub fn mark_for_deletion(&self) {
        self.flags.fetch_or(FLAG_DELETED, AtomicOrdering::Relaxed);
    }

    #[inline(always)]
    pub fn is_marked_for_deletion(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & FLAG_DELETED != 0
    }

    #[inline(always)]
    fn try_set_flag(&self, bit: u8) -> bool {
        let mut current = self.flags.load(AtomicOrdering::Relaxed);
        loop {
            if current & bit != 0 {
                return false;
            }
            match self.flags.compare_exchange_weak(
                current,
                current | bit,
                AtomicOrdering::Acquire,
                AtomicOrdering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline(always)]
    pub fn try_set_refreshing(&self) -> bool {
        self.try_set_flag(FLAG_REFRESHING)
    }

    #[inline(always)]
    pub fn clear_refreshing(&self) {
        self.flags
            .fetch_and(!FLAG_REFRESHING, AtomicOrdering::Release);
    }

    /// Claims the entry for the optimistic queue, de-duplicating it across
    /// cycles: a candidate still waiting to be drained is not offered again.
    #[inline(always)]
    pub fn try_set_refresh_queued(&self) -> bool {
        self.try_set_flag(FLAG_REFRESH_QUEUED)
    }

    #[inline(always)]
    pub fn clear_refresh_queued(&self) {
        self.flags
            .fetch_and(!FLAG_REFRESH_QUEUED, AtomicOrdering::Release);
    }

    /// Hits per minute accumulated since the last renewal.
    ///
    /// Reads against `inserted_at_secs`, which `refresh_record` resets in step
    /// with `hits_at_last_refresh`, so numerator and denominator always cover
    /// the same window.
    #[inline(always)]
    pub fn hits_per_minute_since_refresh(&self, now_secs: u64) -> f64 {
        let hits = self.counters.hit_count.load(AtomicOrdering::Relaxed);
        let base = self
            .counters
            .hits_at_last_refresh
            .load(AtomicOrdering::Relaxed);
        let window_secs = now_secs.saturating_sub(self.inserted_at_secs).max(1);

        (hits.saturating_sub(base) as f64) * 60.0 / (window_secs as f64)
    }

    /// Rebases the rate window on the current hit count. Called on renewal.
    #[inline(always)]
    pub fn note_refreshed(&self) {
        let hits = self.counters.hit_count.load(AtomicOrdering::Relaxed);
        self.counters
            .hits_at_last_refresh
            .store(hits, AtomicOrdering::Relaxed);
    }

    /// Whether the entry should be handed to the background refresh queue.
    ///
    /// `threshold` is the configured fraction of TTL that must have elapsed.
    /// That alone is not enough: a candidate waits up to one cycle to be
    /// scanned and up to one more to be drained, so a purely proportional test
    /// misses any entry whose remaining life is shorter than that. Hence the
    /// lead-time floor — whichever fires first wins. The floor is skipped for
    /// entries whose whole TTL fits inside it, since those cannot be renewed
    /// ahead of expiry at all and would otherwise never leave the queue.
    #[inline(always)]
    pub fn should_refresh(&self, threshold: f64, now_secs: u64, min_lead_secs: u64) -> bool {
        if (self.ttl as u64) > min_lead_secs
            && self.expires_at_secs.saturating_sub(now_secs) <= min_lead_secs
        {
            return true;
        }

        let elapsed = now_secs.saturating_sub(self.inserted_at_secs) as f64;
        elapsed >= (self.ttl as f64) * threshold
    }

    #[inline(always)]
    pub fn record_hit(&self) {
        self.counters
            .hit_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        let now = super::coarse_clock::coarse_now_secs();
        if self.counters.last_access.load(AtomicOrdering::Relaxed) < now {
            self.counters
                .last_access
                .store(now, AtomicOrdering::Relaxed);
        }
    }
}
