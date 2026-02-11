/// Eviction strategy for cache management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionStrategy {
    /// Least Recently Used
    LRU,
    /// Hit rate based eviction (hits per second)
    HitRate,
    /// Least Frequently Used (total hits)
    LFU,
    /// LFU-K (frequency in sliding window of K accesses)
    LFUK,
}

impl EvictionStrategy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "lru" => Self::LRU,
            "lfu" => Self::LFU,
            "lfu-k" | "lfuk" => Self::LFUK,
            _ => Self::HitRate,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LRU => "lru",
            Self::HitRate => "hit_rate",
            Self::LFU => "lfu",
            Self::LFUK => "lfu-k",
        }
    }
}
