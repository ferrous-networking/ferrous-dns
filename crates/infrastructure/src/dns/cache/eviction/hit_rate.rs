use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

/// Estratégia HitRate (taxa de acerto).
///
/// Score = `hits / (hits + 1)`, normalizado entre 0.0 e 1.0.
/// Entradas com mais hits têm score mais alto e sobrevivem ao eviction.
pub struct HitRatePolicy;

impl EvictionPolicy for HitRatePolicy {
    fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        let hits = record.counters.hit_count.load(Ordering::Relaxed);
        let last_access = record.counters.last_access.load(Ordering::Relaxed);
        let age_secs = now_secs.saturating_sub(last_access) as f64;
        let recency = 1.0 / (age_secs + 1.0);
        ((hits as f64) / (hits + 1) as f64) * recency
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::data::{CachedData, DnssecStatus};
    use ferrous_dns_domain::RecordType;
    use std::net::IpAddr;
    use std::sync::Arc;

    fn make_record(hits: u64) -> crate::dns::cache::record::CachedRecord {
        let record = crate::dns::cache::record::CachedRecord::new(
            CachedData::IpAddresses(Arc::new(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])),
            300,
            RecordType::A,
            Some(DnssecStatus::Unknown),
        );
        for _ in 0..hits {
            record.record_hit();
        }
        record
    }

    #[test]
    fn test_hit_rate_score_increases_with_hits() {
        let policy = HitRatePolicy;
        let r0 = make_record(0);
        let r1 = make_record(1);
        let r10 = make_record(10);
        let r100 = make_record(100);

        let s0 = policy.compute_score(&r0, 0);
        let s1 = policy.compute_score(&r1, 0);
        let s10 = policy.compute_score(&r10, 0);
        let s100 = policy.compute_score(&r100, 0);

        assert!(s0 < s1, "0 hits deve ter score menor que 1 hit");
        assert!(s1 < s10, "1 hit deve ter score menor que 10 hits");
        assert!(s10 < s100, "10 hits deve ter score menor que 100 hits");
    }

    #[test]
    fn test_hit_rate_score_is_bounded_between_zero_and_one() {
        let policy = HitRatePolicy;

        let r0 = make_record(0);
        let r_big = make_record(1_000_000);

        let s0 = policy.compute_score(&r0, 0);
        let s_big = policy.compute_score(&r_big, 0);

        assert!(s0 >= 0.0, "Score deve ser >= 0");
        assert!(s_big < 1.0, "Score deve ser < 1.0 (bounded)");
        assert!(s_big >= 0.0, "Score não pode ser negativo em HitRate");
    }

    #[test]
    fn test_hit_rate_score_zero_hits() {
        let policy = HitRatePolicy;
        let record = make_record(0);
        let score = policy.compute_score(&record, 0);
        assert_eq!(score, 0.0);
    }
}
