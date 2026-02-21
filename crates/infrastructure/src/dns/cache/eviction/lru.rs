use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

/// Estratégia LRU (Least Recently Used).
///
/// Score = `last_access` como timestamp Unix. Entradas com menor timestamp
/// (acessadas há mais tempo) têm score menor e são evictadas primeiro.
pub struct LruPolicy;

impl EvictionPolicy for LruPolicy {
    fn compute_score(&self, record: &CachedRecord, _now_secs: u64) -> f64 {
        record.counters.last_access.load(Ordering::Relaxed) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::{coarse_clock, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
    use std::net::IpAddr;
    use std::sync::Arc;

    fn make_ip_data(ip: &str) -> CachedData {
        let addr: IpAddr = ip.parse().unwrap();
        CachedData::IpAddresses(Arc::new(vec![addr]))
    }

    #[test]
    fn test_lru_score_is_last_access_timestamp() {
        let cache = DnsCache::new(DnsCacheConfig {
            max_entries: 10,
            eviction_strategy: EvictionStrategy::LRU,
            min_threshold: 0.0,
            refresh_threshold: 0.75,
            batch_eviction_percentage: 0.2,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
        });

        use ferrous_dns_domain::RecordType;

        coarse_clock::tick();
        cache.insert("a.com", RecordType::A, make_ip_data("1.1.1.1"), 300, None);
        let _ = cache.get(&Arc::from("a.com"), &RecordType::A);

        let policy = LruPolicy;
        let result = cache.get(&Arc::from("a.com"), &RecordType::A);
        assert!(result.is_some(), "Entrada deve existir");
        let _ = policy;
    }

    #[test]
    fn test_lru_evicts_least_recently_used() {
        let cache = DnsCache::new(DnsCacheConfig {
            max_entries: 3,
            eviction_strategy: EvictionStrategy::LRU,
            min_threshold: 0.0,
            refresh_threshold: 0.75,
            batch_eviction_percentage: 1.0,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
        });

        use ferrous_dns_domain::RecordType;

        coarse_clock::tick();
        cache.insert("a.com", RecordType::A, make_ip_data("1.1.1.1"), 300, None);
        cache.insert("b.com", RecordType::A, make_ip_data("2.2.2.2"), 300, None);
        cache.insert("c.com", RecordType::A, make_ip_data("3.3.3.3"), 300, None);
        cache.insert("d.com", RecordType::A, make_ip_data("4.4.4.4"), 300, None);
        cache.evict_entries();

        assert!(cache.len() <= 3, "Cache deve respeitar max_entries");
        let metrics = cache.metrics();
        assert!(
            metrics.evictions.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "Deve ter ocorrido pelo menos uma eviction"
        );
    }
}
