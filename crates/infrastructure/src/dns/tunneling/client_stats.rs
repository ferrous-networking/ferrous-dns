use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Compact tracking key: client subnet hash + apex domain hash.
///
/// Register-sized (16 bytes) for efficient DashMap lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackingKey {
    pub subnet: u64,
    pub apex_hash: u64,
}

impl Hash for TrackingKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.subnet);
        state.write_u64(self.apex_hash);
    }
}

/// Per-client per-apex-domain statistics for tunneling analysis.
///
/// All fields are atomic for lock-free concurrent updates.
/// Approximate size: ~80 bytes per entry.
pub struct ClientApexStats {
    pub query_count: AtomicU32,
    pub unique_subdomain_count: AtomicU32,
    pub txt_query_count: AtomicU32,
    pub nxdomain_count: AtomicU32,
    pub total_count: AtomicU32,
    pub last_seen_ns: AtomicU64,
    pub window_start_ns: AtomicU64,
    /// 256-bit mini bloom filter for approximate unique subdomain counting.
    pub mini_bloom: [AtomicU64; 4],
}

impl ClientApexStats {
    pub fn new(now_ns: u64) -> Self {
        Self {
            query_count: AtomicU32::new(0),
            unique_subdomain_count: AtomicU32::new(0),
            txt_query_count: AtomicU32::new(0),
            nxdomain_count: AtomicU32::new(0),
            total_count: AtomicU32::new(0),
            last_seen_ns: AtomicU64::new(now_ns),
            window_start_ns: AtomicU64::new(now_ns),
            mini_bloom: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Resets counters for a new time window.
    pub fn reset_window(&self, now_ns: u64) {
        self.query_count.store(0, Ordering::Relaxed);
        self.unique_subdomain_count.store(0, Ordering::Relaxed);
        self.txt_query_count.store(0, Ordering::Relaxed);
        self.nxdomain_count.store(0, Ordering::Relaxed);
        self.total_count.store(0, Ordering::Relaxed);
        self.window_start_ns.store(now_ns, Ordering::Relaxed);
        for slot in &self.mini_bloom {
            slot.store(0, Ordering::Relaxed);
        }
    }

    /// Adds a subdomain hash to the mini bloom filter using two independent bit positions.
    /// Returns `true` if the subdomain was probably new (not seen before).
    pub fn bloom_add(&self, subdomain_hash: u64) -> bool {
        let idx1 = (subdomain_hash & 0xFF) as usize;
        let idx2 = ((subdomain_hash >> 8) & 0xFF) as usize;

        let slot1 = idx1 / 64;
        let bit1 = 1u64 << (idx1 % 64);
        let old1 = self.mini_bloom[slot1].fetch_or(bit1, Ordering::Relaxed);

        let slot2 = idx2 / 64;
        let bit2 = 1u64 << (idx2 % 64);
        let old2 = self.mini_bloom[slot2].fetch_or(bit2, Ordering::Relaxed);

        (old1 & bit1) == 0 || (old2 & bit2) == 0
    }
}

/// Sharded concurrent map for per-client per-apex statistics.
pub type StatsMap = DashMap<TrackingKey, ClientApexStats, FxBuildHasher>;

/// Creates a new stats map with FxBuildHasher for fast hashing.
pub fn new_stats_map() -> StatsMap {
    DashMap::with_hasher(FxBuildHasher)
}

/// Computes a subnet key from an IP address using the given prefix lengths.
pub fn subnet_key_from_ip(ip: std::net::IpAddr, v4_prefix: u8, v6_prefix: u8) -> u64 {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if v4_prefix >= 32 {
                0
            } else {
                u32::MAX << (32 - v4_prefix)
            };
            (bits & mask) as u64
        }
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if v6_prefix >= 128 {
                0
            } else {
                u128::MAX << (128 - v6_prefix)
            };
            ((bits & mask) >> 64) as u64
        }
    }
}

/// Computes a fast hash for a domain string using FxHash.
pub fn fx_hash_str(s: &str) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}
