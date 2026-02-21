use super::hit_rate::HitRatePolicy;
use super::lfu::LfuPolicy;
use super::lfuk::LfukPolicy;
use super::lru::LruPolicy;
use super::policy::EvictionPolicy;
use super::strategy::EvictionStrategy;
use crate::dns::cache::record::CachedRecord;

/// Política de eviction ativa com dispatch via enum (zero-cost, sem vtable).
///
/// Cada variante carrega os parâmetros específicos da estratégia.
/// O método `compute_score` usa `#[inline(always)]` para que o compilador
/// possa inlinar cada arm do match e eliminar chamadas indiretas.
///
/// Criado uma vez em `DnsCache::new()` a partir do `DnsCacheConfig`.
pub enum ActiveEvictionPolicy {
    Lru(LruPolicy),
    HitRate(HitRatePolicy),
    Lfu(LfuPolicy),
    Lfuk(LfukPolicy),
}

impl ActiveEvictionPolicy {
    /// Constrói a política ativa a partir do enum de configuração e parâmetros.
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

    /// Calcula o score de eviction delegando à estratégia ativa.
    ///
    /// Score alto = entrada valiosa. Score negativo = abaixo do mínimo
    /// configurado (candidato prioritário para remoção).
    #[inline(always)]
    pub fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        match self {
            Self::Lru(p) => p.compute_score(record, now_secs),
            Self::HitRate(p) => p.compute_score(record, now_secs),
            Self::Lfu(p) => p.compute_score(record, now_secs),
            Self::Lfuk(p) => p.compute_score(record, now_secs),
        }
    }

    /// Retorna o enum `EvictionStrategy` correspondente à política ativa.
    pub fn strategy(&self) -> EvictionStrategy {
        match self {
            Self::Lru(_) => EvictionStrategy::LRU,
            Self::HitRate(_) => EvictionStrategy::HitRate,
            Self::Lfu(_) => EvictionStrategy::LFU,
            Self::Lfuk(_) => EvictionStrategy::LFUK,
        }
    }
}
