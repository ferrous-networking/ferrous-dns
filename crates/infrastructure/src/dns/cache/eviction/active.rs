use super::hit_rate::HitRatePolicy;
use super::lfu::LfuPolicy;
use super::lfuk::LfukPolicy;
use super::lru::LruPolicy;
use super::policy::EvictionPolicy;
use super::strategy::EvictionStrategy;
use crate::dns::cache::record::CachedRecord;

pub enum ActiveEvictionPolicy {
    Lru(LruPolicy),
    HitRate(HitRatePolicy),
    Lfu(LfuPolicy),
    Lfuk(LfukPolicy),
}

impl ActiveEvictionPolicy {
    pub fn from_config(
        strategy: EvictionStrategy,
        min_frequency: u64,
        min_lfuk_score: f64,
        lfuk_k_value: f64,
    ) -> Self {
        match strategy {
            EvictionStrategy::LRU => Self::Lru(LruPolicy),
            EvictionStrategy::HitRate => Self::HitRate(HitRatePolicy),
            EvictionStrategy::LFU => Self::Lfu(LfuPolicy { min_frequency }),
            EvictionStrategy::LFUK => Self::Lfuk(LfukPolicy {
                min_lfuk_score,
                k_value: lfuk_k_value,
            }),
        }
    }

    #[inline(always)]
    pub fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        match self {
            Self::Lru(p) => p.compute_score(record, now_secs),
            Self::HitRate(p) => p.compute_score(record, now_secs),
            Self::Lfu(p) => p.compute_score(record, now_secs),
            Self::Lfuk(p) => p.compute_score(record, now_secs),
        }
    }

    pub fn strategy(&self) -> EvictionStrategy {
        match self {
            Self::Lru(_) => EvictionStrategy::LRU,
            Self::HitRate(_) => EvictionStrategy::HitRate,
            Self::Lfu(_) => EvictionStrategy::LFU,
            Self::Lfuk(_) => EvictionStrategy::LFUK,
        }
    }
}
