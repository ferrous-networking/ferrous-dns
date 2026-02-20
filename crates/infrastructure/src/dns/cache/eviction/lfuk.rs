use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

/// Estratégia LFUK (Least Frequently Used with K-distance).
///
/// Combina frequência de acesso com recência: entradas acessadas frequentemente
/// e recentemente têm score alto. Fórmula:
///
/// ```text
/// score = (hits / age^k) * (1 / (now - last_access + 1))
/// ```
///
/// Se `min_lfuk_score > 0.0` e `score < min_lfuk_score`, aplica penalidade
/// (score negativo), tornando a entrada candidata prioritária para eviction.
///
/// Requer `access_history` no [`CachedRecord`] para tracking de acessos.
pub struct LfukPolicy {
    pub min_lfuk_score: f64,
}

impl EvictionPolicy for LfukPolicy {
    fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        let access_time = record.last_access.load(Ordering::Relaxed) as f64;
        let hits = record.hit_count.load(Ordering::Relaxed) as f64;
        let age = record.inserted_at_secs as f64;
        let k_value = 0.5_f64;

        let score =
            hits / (age.powf(k_value).max(1.0)) * (1.0 / (now_secs as f64 - access_time + 1.0));

        if self.min_lfuk_score > 0.0 && score < self.min_lfuk_score {
            // Score negativo indica "abaixo do mínimo" — free-evict elegível
            score - self.min_lfuk_score
        } else {
            score
        }
    }

    fn uses_access_history(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::data::{CachedData, DnssecStatus};
    use ferrous_dns_domain::RecordType;
    use std::net::IpAddr;
    use std::sync::Arc;

    fn make_record_with_hits(hits: u64) -> crate::dns::cache::record::CachedRecord {
        let record = crate::dns::cache::record::CachedRecord::new(
            CachedData::IpAddresses(Arc::new(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])),
            300,
            RecordType::A,
            true, // use_lfuk = true → access_history alocado
            Some(DnssecStatus::Unknown),
        );
        for _ in 0..hits {
            record.record_hit();
        }
        record
    }

    #[test]
    fn test_lfuk_uses_access_history() {
        let policy = LfukPolicy {
            min_lfuk_score: 0.0,
        };
        assert!(
            policy.uses_access_history(),
            "LFUK deve usar access_history"
        );
    }

    #[test]
    fn test_lfuk_score_below_min_is_negative() {
        let policy = LfukPolicy {
            min_lfuk_score: 1.5,
        };
        // Record com 0 hits → score ≈ 0 → score - 1.5 < 0
        let record = make_record_with_hits(0);
        let score = policy.compute_score(&record, 1_000_000);
        assert!(
            score < 0.0,
            "Score deve ser negativo quando abaixo de min_lfuk_score"
        );
    }

    #[test]
    fn test_lfuk_score_with_many_hits_and_recent_access() {
        let policy = LfukPolicy {
            min_lfuk_score: 0.0,
        };
        let record = make_record_with_hits(20);
        // now_secs próximo de last_access → recência alta → score alto
        let now_secs = crate::dns::cache::coarse_clock::coarse_now_secs();
        let score = policy.compute_score(&record, now_secs);
        assert!(
            score >= 0.0,
            "Entrada com muitos hits recentes deve ter score >= 0"
        );
    }
}
