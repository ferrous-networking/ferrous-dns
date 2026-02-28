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

    #[inline(always)]
    pub fn compute_score_from_snapshot(
        &self,
        hit_count: u64,
        last_access: u64,
        inserted_at: u64,
        _expires_at: u64,
        now_secs: u64,
    ) -> f64 {
        match self {
            Self::Lru(_) => last_access as f64,
            Self::HitRate(_) => {
                let age_secs = now_secs.saturating_sub(last_access) as f64;
                let recency = 1.0 / (age_secs + 1.0);
                ((hit_count as f64) / (hit_count + 1) as f64) * recency
            }
            Self::Lfu(p) => {
                if p.min_frequency > 0 && hit_count < p.min_frequency {
                    -(p.min_frequency as f64 - hit_count as f64)
                } else {
                    hit_count as f64
                }
            }
            Self::Lfuk(p) => {
                let hits = hit_count as f64;
                if hits == 0.0 {
                    return p.min_lfuk_score;
                }
                let age_secs = now_secs.saturating_sub(inserted_at).max(1) as f64;
                let idle_secs = now_secs.saturating_sub(last_access) as f64;
                let age_decay = if (p.k_value - 0.5).abs() < f64::EPSILON {
                    age_secs.sqrt().max(1.0)
                } else {
                    age_secs.powf(p.k_value).max(1.0)
                };
                let score = hits / age_decay * (1.0 / (idle_secs + 1.0));
                if p.min_lfuk_score > 0.0 && score < p.min_lfuk_score {
                    score - p.min_lfuk_score
                } else {
                    score
                }
            }
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
