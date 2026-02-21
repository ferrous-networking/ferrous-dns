use super::storage::DnsCache;
use std::sync::atomic::Ordering as AtomicOrdering;
use tracing::debug;

impl DnsCache {
    /// Remove entradas marcadas para deleção (lazy deletion).
    ///
    /// Entradas expiradas **não** são removidas aqui: são gerenciadas pelo
    /// eviction system por score quando o cache encher, ou pelo ciclo de refresh
    /// urgente quando dentro da `access_window`. Isso permite que entradas
    /// populares expiradas sobrevivam até serem renovadas ou removidas por score baixo.
    pub fn compact(&self) -> usize {
        let before = self.cache.len();
        self.cache
            .retain(|_, record| !record.is_marked_for_deletion());
        let removed = before.saturating_sub(self.cache.len());

        if removed > 0 {
            self.metrics
                .compactions
                .fetch_add(1, AtomicOrdering::Relaxed);

            debug!(
                removed,
                cache_size = self.cache.len(),
                "Cache compaction completed"
            );
        }

        self.compaction_counter
            .fetch_add(1, AtomicOrdering::Relaxed);

        removed
    }

    pub fn compaction_count(&self) -> usize {
        self.compaction_counter.load(AtomicOrdering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::cache::{coarse_clock, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
    use ferrous_dns_domain::RecordType;
    use std::net::IpAddr;
    use std::sync::Arc;

    fn make_cache(access_window_secs: u64) -> DnsCache {
        DnsCache::new(DnsCacheConfig {
            max_entries: 100,
            eviction_strategy: EvictionStrategy::HitRate,
            min_threshold: 0.0,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.2,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
        })
    }

    fn make_cname(name: &str) -> CachedData {
        CachedData::CanonicalName(Arc::from(name))
    }

    fn make_ip(ip: &str) -> CachedData {
        let addr: IpAddr = ip.parse().unwrap();
        CachedData::IpAddresses(Arc::new(vec![addr]))
    }

    /// Entradas expiradas permanecem no cache até `get()` as marcar para deleção;
    /// `compact()` remove apenas entradas com `FLAG_DELETED` set.
    #[test]
    fn test_compact_retains_expired_entries() {
        let cache = make_cache(7200);
        coarse_clock::tick();

        cache.insert(
            "expired.test",
            RecordType::CNAME,
            make_cname("alias"),
            1,
            None,
        );

        std::thread::sleep(std::time::Duration::from_secs(2));
        coarse_clock::tick();

        let removed = cache.compact();
        assert_eq!(
            removed, 0,
            "compact() não deve remover entradas expiradas (apenas marked_for_deletion)"
        );
        assert_eq!(cache.len(), 1, "Entrada expirada deve permanecer no cache");
    }

    /// `get()` marca entradas expiradas para deleção; `compact()` as remove em seguida.
    #[test]
    fn test_compact_removes_marked_for_deletion() {
        let cache = make_cache(7200);
        coarse_clock::tick();

        cache.insert(
            "to-delete.test",
            RecordType::CNAME,
            make_cname("alias"),
            1,
            None,
        );

        std::thread::sleep(std::time::Duration::from_secs(2));
        coarse_clock::tick();

        let result = cache.get(&Arc::from("to-delete.test"), &RecordType::CNAME);
        assert!(
            result.is_none(),
            "get() deve retornar None para entrada expirada"
        );

        let removed = cache.compact();
        assert_eq!(
            removed, 1,
            "compact() deve remover entradas marked_for_deletion"
        );
        assert_eq!(cache.len(), 0);
    }

    /// Entradas válidas (não expiradas, não marcadas) nunca são removidas por compact().
    #[test]
    fn test_compact_retains_valid_entries() {
        let cache = make_cache(7200);
        coarse_clock::tick();

        cache.insert("valid.test", RecordType::A, make_ip("1.1.1.1"), 3600, None);

        let removed = cache.compact();
        assert_eq!(removed, 0, "Entradas válidas não devem ser removidas");
        assert_eq!(cache.len(), 1);
    }
}
