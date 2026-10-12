use super::coarse_clock::coarse_now_secs;
use super::data::{CachedData, CachedDnssecStatus};
use super::schedule::refresh_due_at;
use ferrous_dns_domain::RecordType;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering as AtomicOrdering};

const FLAG_DELETED: u8 = 0b001;
const FLAG_REFRESHING: u8 = 0b010;
const FLAG_PERMANENT: u8 = 0b100;
/// Set while a refresh timer is pending for the entry, and kept when the
/// renewal failed or the timer was shed, until compaction re-arms it.
///
/// Clear means the entry's timer fired while the entry was outside the
/// access window, so nothing will renew it. A hit on a clear entry re-arms
/// it, which is how a name that comes back into use gets renewed again. A
/// failure or a shed timer keeps the bit set on purpose, so a hit cannot
/// turn a failing upstream or a full inbox into one more attempt per hit.
const FLAG_REFRESH_ARMED: u8 = 0b1000;
/// Set when the answer came from the configured local DNS server, so a hit
/// stays exempt from checks that trust local answers (rebinding, NXDOMAIN budget).
const FLAG_LOCAL_DNS: u8 = 0b1_0000;
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

    /// Marks an answer from the local DNS server; see [`Self::is_local_dns`].
    #[inline]
    pub fn with_local_dns(mut self) -> Self {
        *self.flags.get_mut() |= FLAG_LOCAL_DNS;
        self
    }

    /// Whether the local DNS server gave this answer. Never cleared: a renewal
    /// re-resolves the same name, which the same server owns.
    #[inline(always)]
    pub fn is_local_dns(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & FLAG_LOCAL_DNS != 0
    }

    /// Marks a record not yet shared as having a refresh timer on its way;
    /// see `FLAG_REFRESH_ARMED`.
    #[inline]
    pub fn armed(mut self) -> Self {
        *self.flags.get_mut() |= FLAG_REFRESH_ARMED;
        self
    }

    /// Seconds a client may hold the answer. A permanent entry never expires,
    /// so it reports its configured TTL rather than the distance to `u64::MAX`.
    #[inline(always)]
    pub fn remaining_ttl_at_secs(&self, now_secs: u64) -> u32 {
        if self.is_permanent() {
            self.ttl
        } else {
            self.expires_at_secs.saturating_sub(now_secs) as u32
        }
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

    /// See `FLAG_REFRESH_ARMED`.
    #[inline(always)]
    pub fn is_refresh_armed(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & FLAG_REFRESH_ARMED != 0
    }

    /// Whether a hit should arm this entry's refresh timer again: it is not a
    /// local record, which is never renewed, and its last timer was spent
    /// without renewing it. One load, since every L2 hit asks.
    #[inline(always)]
    pub fn needs_refresh_rearm(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & (FLAG_REFRESH_ARMED | FLAG_PERMANENT) == 0
    }

    #[inline(always)]
    pub fn is_refreshing(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & FLAG_REFRESHING != 0
    }

    /// Claims the right to arm the entry's refresh timer; `false` if it is
    /// already armed.
    #[inline(always)]
    pub fn try_arm_refresh(&self) -> bool {
        self.try_set_flag(FLAG_REFRESH_ARMED)
    }

    #[inline(always)]
    pub fn disarm_refresh(&self) {
        self.flags
            .fetch_and(!FLAG_REFRESH_ARMED, AtomicOrdering::Release);
    }

    /// The second this entry falls due for renewal; see [`refresh_due_at`].
    #[inline(always)]
    pub fn refresh_due_at_secs(&self, threshold: f64) -> u64 {
        refresh_due_at(self.inserted_at_secs, self.ttl, threshold)
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

    #[inline(always)]
    pub fn record_hit(&self) {
        self.record_hits(1);
    }

    /// Counts `count` hits at once: the batch an L1 copy hands over, or one
    /// L2 hit.
    #[inline(always)]
    pub fn record_hits(&self, count: u64) {
        self.counters
            .hit_count
            .fetch_add(count, AtomicOrdering::Relaxed);
        let now = super::coarse_clock::coarse_now_secs();
        if self.counters.last_access.load(AtomicOrdering::Relaxed) < now {
            self.counters
                .last_access
                .store(now, AtomicOrdering::Relaxed);
        }
    }
}
