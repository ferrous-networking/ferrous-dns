use super::data::{CachedData, DnssecStatus};
use ferrous_dns_domain::RecordType;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct CachedRecord {
    pub data: CachedData,
    pub dnssec_status: DnssecStatus,
    pub expires_at: Instant,
    pub inserted_at: Instant,
    pub hit_count: AtomicU64,
    pub last_access: AtomicU64,
    pub ttl: u32,
    pub record_type: RecordType,
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
            expires_at: self.expires_at,
            inserted_at: self.inserted_at,
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
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let access_history = if use_lfuk {
            Some(Box::new(RwLock::new(VecDeque::with_capacity(10))))
        } else {
            None
        };

        Self {
            data,
            dnssec_status: dnssec_status.unwrap_or(DnssecStatus::Unknown),
            expires_at: now + Duration::from_secs(ttl as u64),
            inserted_at: now,
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_unix),
            ttl,
            record_type,
            access_history,
            marked_for_deletion: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            permanent: false,
        }
    }

    pub fn permanent(data: CachedData, ttl: u32, record_type: RecordType) -> Self {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = now + Duration::from_secs(365 * 24 * 60 * 60); 

        Self {
            data,
            dnssec_status: DnssecStatus::Unknown, 
            expires_at,
            inserted_at: now,
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_unix),
            ttl,
            record_type,
            access_history: None, 
            marked_for_deletion: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            permanent: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        if self.permanent {
            return false;
        }
        Instant::now() >= self.expires_at
    }

    pub fn is_stale_usable(&self) -> bool {
        let now = Instant::now();
        let age = now.duration_since(self.inserted_at).as_secs();
        let max_stale_age = (self.ttl as u64) * 2;

        self.is_expired() && age < max_stale_age
    }

    pub fn age_secs(&self) -> u64 {
        Instant::now().duration_since(self.inserted_at).as_secs()
    }

    pub fn mark_for_deletion(&self) {
        self.marked_for_deletion
            .store(true, AtomicOrdering::Relaxed);
    }

    pub fn is_marked_for_deletion(&self) -> bool {
        self.marked_for_deletion.load(AtomicOrdering::Relaxed)
    }

    pub fn should_refresh(&self, threshold: f64) -> bool {
        let elapsed = self.inserted_at.elapsed().as_secs_f64();
        let ttl_seconds = self.ttl as f64;
        elapsed >= (ttl_seconds * threshold)
    }

    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, AtomicOrdering::Relaxed);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_access.store(now_unix, AtomicOrdering::Relaxed);
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(AtomicOrdering::Relaxed) as f64;
        let age_secs = self.inserted_at.elapsed().as_secs_f64();

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
