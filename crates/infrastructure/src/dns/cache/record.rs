use super::coarse_clock::coarse_now_secs;
use super::data::{CachedData, DnssecStatus};
use ferrous_dns_domain::RecordType;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::RwLock;
use std::time::Instant;

#[derive(Debug)]
pub struct CachedRecord {
    pub data: CachedData,
    pub dnssec_status: DnssecStatus,
    /// Expiry as a coarse Unix timestamp (seconds).  Avoids `Instant::now()`
    /// in the read hot path — coarse_now_secs() is an AtomicU64 load (~3 ns)
    /// vs a VDSO/syscall call (~20 ns – 2 µs depending on kernel config).
    pub expires_at_secs: u64,
    /// Insertion time as a coarse Unix timestamp (seconds).
    pub inserted_at_secs: u64,
    pub hit_count: AtomicU64,
    pub last_access: AtomicU64,
    pub ttl: u32,
    pub record_type: RecordType,
    /// Per-access timestamps used only by the LFUK eviction scorer.
    /// Uses `Instant` for sub-second precision in the scoring window.
    pub access_history: Option<Box<RwLock<VecDeque<Instant>>>>,
    pub marked_for_deletion: AtomicBool,
    pub refreshing: AtomicBool,
    pub permanent: bool,
}

impl Clone for CachedRecord {
    fn clone(&self) -> Self {
        let access_history = if self.access_history.is_some() {
            Some(Box::new(RwLock::new(VecDeque::with_capacity(10))))
        } else {
            None
        };

        Self {
            data: self.data.clone(),
            dnssec_status: self.dnssec_status,
            expires_at_secs: self.expires_at_secs,
            inserted_at_secs: self.inserted_at_secs,
            hit_count: AtomicU64::new(self.hit_count.load(AtomicOrdering::Relaxed)),
            last_access: AtomicU64::new(self.last_access.load(AtomicOrdering::Relaxed)),
            ttl: self.ttl,
            record_type: self.record_type,
            access_history,
            marked_for_deletion: AtomicBool::new(
                self.marked_for_deletion.load(AtomicOrdering::Relaxed),
            ),
            refreshing: AtomicBool::new(self.refreshing.load(AtomicOrdering::Relaxed)),
            permanent: self.permanent,
        }
    }
}

impl CachedRecord {
    pub fn new(
        data: CachedData,
        ttl: u32,
        record_type: RecordType,
        use_lfuk: bool,
        dnssec_status: Option<DnssecStatus>,
    ) -> Self {
        let now_secs = coarse_now_secs();

        let access_history = if use_lfuk {
            Some(Box::new(RwLock::new(VecDeque::with_capacity(10))))
        } else {
            None
        };

        Self {
            data,
            dnssec_status: dnssec_status.unwrap_or(DnssecStatus::Unknown),
            expires_at_secs: now_secs + ttl as u64,
            inserted_at_secs: now_secs,
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_secs),
            ttl,
            record_type,
            access_history,
            marked_for_deletion: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            permanent: false,
        }
    }

    pub fn permanent(data: CachedData, ttl: u32, record_type: RecordType) -> Self {
        let now_secs = coarse_now_secs();

        Self {
            data,
            dnssec_status: DnssecStatus::Unknown,
            expires_at_secs: u64::MAX,
            inserted_at_secs: now_secs,
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_secs),
            ttl,
            record_type,
            access_history: None,
            marked_for_deletion: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            permanent: true,
        }
    }

    #[inline(always)]
    pub fn is_expired(&self) -> bool {
        if self.permanent {
            return false;
        }
        coarse_now_secs() >= self.expires_at_secs
    }

    /// Like `is_expired` but reuses a pre-computed `now_secs` to avoid a
    /// redundant `coarse_now_secs()` call when the caller already has one.
    #[inline(always)]
    pub fn is_expired_at_secs(&self, now_secs: u64) -> bool {
        if self.permanent {
            return false;
        }
        now_secs >= self.expires_at_secs
    }

    #[inline(always)]
    pub fn is_stale_usable(&self) -> bool {
        let now_secs = coarse_now_secs();
        let age = now_secs.saturating_sub(self.inserted_at_secs);
        let max_stale_age = (self.ttl as u64) * 2;

        now_secs >= self.expires_at_secs && age < max_stale_age
    }

    /// Like `is_stale_usable` but reuses a pre-computed `now_secs` to avoid a
    /// redundant `coarse_now_secs()` call when the caller already has one.
    #[inline(always)]
    pub fn is_stale_usable_at_secs(&self, now_secs: u64) -> bool {
        let age = now_secs.saturating_sub(self.inserted_at_secs);
        let max_stale_age = (self.ttl as u64) * 2;

        now_secs >= self.expires_at_secs && age < max_stale_age
    }

    pub fn age_secs(&self) -> u64 {
        coarse_now_secs().saturating_sub(self.inserted_at_secs)
    }

    pub fn mark_for_deletion(&self) {
        self.marked_for_deletion
            .store(true, AtomicOrdering::Relaxed);
    }

    #[inline(always)]
    pub fn is_marked_for_deletion(&self) -> bool {
        self.marked_for_deletion.load(AtomicOrdering::Relaxed)
    }

    #[inline(always)]
    pub fn should_refresh(&self, threshold: f64) -> bool {
        let elapsed = coarse_now_secs().saturating_sub(self.inserted_at_secs) as f64;
        let ttl_seconds = self.ttl as f64;
        elapsed >= (ttl_seconds * threshold)
    }

    #[inline(always)]
    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, AtomicOrdering::Relaxed);
        self.last_access.store(
            super::coarse_clock::coarse_now_secs(),
            AtomicOrdering::Relaxed,
        );
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(AtomicOrdering::Relaxed) as f64;
        let age_secs = coarse_now_secs().saturating_sub(self.inserted_at_secs) as f64;

        if age_secs > 0.0 {
            hits / age_secs
        } else {
            hits
        }
    }

    pub fn frequency(&self) -> u64 {
        self.hit_count.load(AtomicOrdering::Relaxed)
    }

    pub fn lfuk_score(&self) -> f64 {
        if let Some(ref history) = self.access_history {
            if let Ok(hist) = history.try_read() {
                if hist.len() < 2 {
                    return 0.0;
                }

                let oldest = hist.front().unwrap();
                let newest = hist.back().unwrap();
                let timespan = newest.duration_since(*oldest).as_secs_f64();

                if timespan > 0.0 {
                    hist.len() as f64 / timespan
                } else {
                    hist.len() as f64
                }
            } else {
                self.hit_rate()
            }
        } else {
            0.0
        }
    }
}
