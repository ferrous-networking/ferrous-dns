/// Eviction strategy for cache management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionStrategy {
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
            "lfu" => Self::LFU,
            "lfu-k" | "lfuk" => Self::LFUK,
            _ => Self::HitRate,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HitRate => "hit_rate",
            Self::LFU => "lfu",
            Self::LFUK => "lfu-k",
        }
    }
}
