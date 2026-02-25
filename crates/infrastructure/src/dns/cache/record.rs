use super::coarse_clock::coarse_now_secs;
use super::data::{CachedData, DnssecStatus};
use ferrous_dns_domain::RecordType;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering as AtomicOrdering};

const FLAG_DELETED: u8 = 0b001;
const FLAG_REFRESHING: u8 = 0b010;
const FLAG_PERMANENT: u8 = 0b100;
const STALE_GRACE_PERIOD_MULTIPLIER: u64 = 2;

#[repr(align(64))]
pub struct HotCounters {
    pub hit_count: AtomicU64,
    pub last_access: AtomicU64,
}

impl HotCounters {
    fn new(now_secs: u64) -> Self {
        Self {
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_secs),
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
            .finish()
    }
}

#[derive(Debug)]
pub struct CachedRecord {
    pub data: CachedData,
    pub dnssec_status: DnssecStatus,
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
        dnssec_status: Option<DnssecStatus>,
    ) -> Self {
        let now_secs = coarse_now_secs();

        Self {
            data,
            dnssec_status: dnssec_status.unwrap_or(DnssecStatus::Unknown),
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
            dnssec_status: DnssecStatus::Unknown,
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
    pub fn is_stale_usable(&self) -> bool {
        let now_secs = coarse_now_secs();
        let age = now_secs.saturating_sub(self.inserted_at_secs);
        let max_stale_age = (self.ttl as u64) * STALE_GRACE_PERIOD_MULTIPLIER;

        now_secs >= self.expires_at_secs && age < max_stale_age
    }

    #[inline(always)]
    pub fn is_stale_usable_at_secs(&self, now_secs: u64) -> bool {
        let age = now_secs.saturating_sub(self.inserted_at_secs);
        let max_stale_age = (self.ttl as u64) * STALE_GRACE_PERIOD_MULTIPLIER;

        now_secs >= self.expires_at_secs && age < max_stale_age
    }

    pub fn mark_for_deletion(&self) {
        self.flags.fetch_or(FLAG_DELETED, AtomicOrdering::Relaxed);
    }

    #[inline(always)]
    pub fn is_marked_for_deletion(&self) -> bool {
        self.flags.load(AtomicOrdering::Relaxed) & FLAG_DELETED != 0
    }

    #[inline(always)]
    pub fn try_set_refreshing(&self) -> bool {
        let mut current = self.flags.load(AtomicOrdering::Relaxed);
        loop {
            if current & FLAG_REFRESHING != 0 {
                return false;
            }
            match self.flags.compare_exchange_weak(
                current,
                current | FLAG_REFRESHING,
                AtomicOrdering::Acquire,
                AtomicOrdering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline(always)]
    pub fn clear_refreshing(&self) {
        self.flags
            .fetch_and(!FLAG_REFRESHING, AtomicOrdering::Release);
    }

    #[inline(always)]
    pub fn should_refresh(&self, threshold: f64) -> bool {
        let elapsed = coarse_now_secs().saturating_sub(self.inserted_at_secs) as f64;
        let ttl_seconds = self.ttl as f64;
        elapsed >= (ttl_seconds * threshold)
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

    pub fn hit_rate(&self) -> f64 {
        let hits = self.counters.hit_count.load(AtomicOrdering::Relaxed) as f64;
        let age_secs = coarse_now_secs().saturating_sub(self.inserted_at_secs) as f64;

        if age_secs > 0.0 {
            hits / age_secs
        } else {
            hits
        }
    }
}
