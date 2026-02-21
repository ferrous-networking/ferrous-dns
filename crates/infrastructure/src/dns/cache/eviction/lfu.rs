use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

/// Estratégia LFU (Least Frequently Used).
///
/// Score = `hit_count`. Entradas com menos hits são evictadas primeiro.
///
/// Se `min_frequency > 0`, entradas abaixo do threshold recebem score negativo
/// (penalidade), tornando-as as primeiras candidatas ao eviction independente
/// das demais.
pub struct LfuPolicy {
    pub min_frequency: u64,
}

impl EvictionPolicy for LfuPolicy {
    fn compute_score(&self, record: &CachedRecord, _now_secs: u64) -> f64 {
        let hits = record.counters.hit_count.load(Ordering::Relaxed);
        if self.min_frequency > 0 && hits < self.min_frequency {
            -(self.min_frequency as f64 - hits as f64)
        } else {
            hits as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::{coarse_clock, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
    use ferrous_dns_domain::RecordType;
    use std::net::IpAddr;
    use std::sync::Arc;

    fn make_ip_data(ip: &str) -> CachedData {
        let addr: IpAddr = ip.parse().unwrap();
        CachedData::IpAddresses(Arc::new(vec![addr]))
    }

    #[test]
    fn test_lfu_score_below_min_frequency_is_negative() {
        let policy = LfuPolicy { min_frequency: 10 };

        let cache = DnsCache::new(DnsCacheConfig {
            max_entries: 10,
            eviction_strategy: EvictionStrategy::LFU,
            min_threshold: 0.0,
            refresh_threshold: 0.75,
            batch_eviction_percentage: 0.2,
            adaptive_thresholds: false,
            min_frequency: 10,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
        });

        coarse_clock::tick();
        cache.insert(
            "test.com",
            RecordType::A,
            make_ip_data("1.1.1.1"),
            300,
            None,
        );

        for _ in 0..3 {
            cache.get(&Arc::from("test.com"), &RecordType::A);
        }

        use crate::dns::cache::data::CachedData as CD;
        use crate::dns::cache::data::DnssecStatus;
        let record = CachedRecord::new(
            CD::IpAddresses(Arc::new(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])),
            300,
            RecordType::A,
            Some(DnssecStatus::Unknown),
        );
        for _ in 0..3 {
            record.record_hit();
        }

        let score = policy.compute_score(&record, 0);
        assert!(
            score < 0.0,
            "Score deve ser negativo quando hits ({}) < min_frequency (10)",
            3
        );
        assert_eq!(
            score,
            -(10.0 - 3.0),
            "Score deve ser -(min_frequency - hits)"
        );
    }

    #[test]
    fn test_lfu_score_above_min_frequency_is_positive() {
        let policy = LfuPolicy { min_frequency: 5 };

        use crate::dns::cache::data::{CachedData as CD, DnssecStatus};
        use std::net::IpAddr;
        let record = CachedRecord::new(
            CD::IpAddresses(Arc::new(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])),
            300,
            RecordType::A,
            Some(DnssecStatus::Unknown),
        );
        for _ in 0..15 {
            record.record_hit();
        }

        let score = policy.compute_score(&record, 0);
        assert!(
            score > 0.0,
            "Score deve ser positivo quando hits (15) >= min_frequency (5)"
        );
        assert_eq!(score, 15.0);
    }

    #[test]
    fn test_lfu_score_zero_min_frequency_returns_raw_hits() {
        let policy = LfuPolicy { min_frequency: 0 };

        use crate::dns::cache::data::{CachedData as CD, DnssecStatus};
        use std::net::IpAddr;
        let record = CachedRecord::new(
            CD::IpAddresses(Arc::new(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])),
            300,
            RecordType::A,
            Some(DnssecStatus::Unknown),
        );
        for _ in 0..7 {
            record.record_hit();
        }

        let score = policy.compute_score(&record, 0);
        assert_eq!(
            score, 7.0,
            "Com min_frequency=0, score deve ser raw hit_count"
        );
    }
}
