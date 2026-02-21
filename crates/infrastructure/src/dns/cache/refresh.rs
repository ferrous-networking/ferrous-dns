use super::coarse_clock::coarse_now_secs;
use super::storage::DnsCache;
use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    /// Retorna entradas candidatas ao refresh otimista.
    ///
    /// Uma entrada é candidata se:
    /// - Não está marcada para deleção, não é resposta negativa, não é HTTPS
    /// - Está dentro da janela de acesso configurada:
    ///   `hit_count > 0 && (now - last_access) <= access_window_secs`
    ///
    /// Para entradas **expiradas** dentro da janela: são candidatos **urgentes**
    /// (TTL já passou, renovação imediata necessária). Incluídas se ainda estiverem
    /// dentro do grace period `is_stale_usable` (2×TTL).
    ///
    /// Para entradas **válidas** dentro da janela: candidatos normais pelo threshold
    /// de refresh (`refresh_threshold`, ex.: 75% do TTL decorrido).
    ///
    /// Entradas **fora da janela** não recebem refresh proativo. O próximo acesso
    /// atualiza `last_access` via `record_hit()`, re-inserindo-as na janela.
    pub fn get_refresh_candidates(&self) -> Vec<(CompactString, RecordType)> {
        let mut candidates = Vec::with_capacity(16);
        let now = coarse_now_secs();
        let sample_period = self.refresh_sample_period;
        let mut idx: u64 = 0;

        for entry in self.cache.iter() {
            idx += 1;
            if sample_period > 1 && !idx.is_multiple_of(sample_period) {
                continue;
            }
            let record = entry.value();

            if record.is_marked_for_deletion() {
                continue;
            }

            if record.data.is_negative() {
                continue;
            }

            let key = entry.key();
            if matches!(key.record_type, RecordType::HTTPS) {
                continue;
            }

            let hit_count = record.counters.hit_count.load(AtomicOrdering::Relaxed);
            let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
            let age_since_access = now.saturating_sub(last_access);
            let within_window = hit_count > 0 && age_since_access <= self.access_window_secs;

            if !within_window {
                continue;
            }

            if record.is_expired_at_secs(now) {
                if record.is_stale_usable_at_secs(now) && record.try_set_refreshing() {
                    candidates.push((key.domain.clone(), key.record_type));
                }
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            if record.try_set_refreshing() {
                candidates.push((key.domain.clone(), key.record_type));
            }
        }

        candidates
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.clear_refreshing();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::cache::{coarse_clock, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
    use ferrous_dns_domain::RecordType;
    use std::sync::Arc;

    fn make_cache_with_window(access_window_secs: u64) -> DnsCache {
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

    /// Entrada expirada dentro da janela de acesso é candidato urgente de refresh
    /// enquanto ainda estiver no grace period (`inserted_at + 2×TTL`).
    #[test]
    fn test_refresh_includes_expired_entry_within_window() {
        let cache = make_cache_with_window(7200);
        coarse_clock::tick();

        cache.insert(
            "expired-window.test",
            RecordType::CNAME,
            make_cname("alias"),
            2,
            None,
        );
        let _ = cache.get(&Arc::from("expired-window.test"), &RecordType::CNAME);

        std::thread::sleep(std::time::Duration::from_secs(3));
        coarse_clock::tick();

        let candidates = cache.get_refresh_candidates();
        assert!(
            candidates.iter().any(|(d, _)| d == "expired-window.test"),
            "Entrada expirada dentro da janela deve ser candidato urgente. Candidatos: {:?}",
            candidates
        );
    }

    /// Entrada expirada FORA da janela (window=0) → NÃO é candidato.
    #[test]
    fn test_refresh_excludes_expired_entry_outside_window() {
        let cache = make_cache_with_window(0);
        coarse_clock::tick();

        cache.insert(
            "expired-no-window.test",
            RecordType::CNAME,
            make_cname("alias"),
            1,
            None,
        );
        let _ = cache.get(&Arc::from("expired-no-window.test"), &RecordType::CNAME);

        std::thread::sleep(std::time::Duration::from_secs(2));
        coarse_clock::tick();

        let candidates = cache.get_refresh_candidates();
        assert!(
            !candidates
                .iter()
                .any(|(d, _)| d == "expired-no-window.test"),
            "Entrada expirada fora da janela não deve ser candidato. Candidatos: {:?}",
            candidates
        );
    }

    /// Entrada válida SEM hits → NÃO é candidato (fora da janela por falta de hits).
    #[test]
    fn test_refresh_excludes_entry_without_hits() {
        let cache = make_cache_with_window(7200);
        coarse_clock::tick();

        cache.insert(
            "no-hits.test",
            RecordType::CNAME,
            make_cname("alias"),
            3600,
            None,
        );

        let candidates = cache.get_refresh_candidates();
        assert!(
            !candidates.iter().any(|(d, _)| d == "no-hits.test"),
            "Entrada sem hits não deve ser candidato. Candidatos: {:?}",
            candidates
        );
    }

    /// Entrada válida COM hit dentro da janela → candidato normal.
    #[test]
    fn test_refresh_includes_valid_entry_within_window() {
        let cache = make_cache_with_window(7200);
        coarse_clock::tick();

        cache.insert(
            "valid-hit.test",
            RecordType::CNAME,
            make_cname("alias"),
            3600,
            None,
        );
        let _ = cache.get(&Arc::from("valid-hit.test"), &RecordType::CNAME);

        let candidates = cache.get_refresh_candidates();
        assert!(
            candidates.iter().any(|(d, _)| d == "valid-hit.test"),
            "Entrada válida com hit dentro da janela deve ser candidata. Candidatos: {:?}",
            candidates
        );
    }

    /// Entradas com refreshing=true não são retornadas como candidatos (compare_exchange).
    #[test]
    fn test_refresh_skips_already_refreshing_entries() {
        let cache = make_cache_with_window(7200);
        coarse_clock::tick();

        cache.insert(
            "refreshing.test",
            RecordType::CNAME,
            make_cname("alias"),
            3600,
            None,
        );
        let _ = cache.get(&Arc::from("refreshing.test"), &RecordType::CNAME);

        let key = crate::dns::cache::key::CacheKey::new("refreshing.test", RecordType::CNAME);
        if let Some(entry) = cache.cache.get(&key) {
            entry.try_set_refreshing();
        }

        let candidates = cache.get_refresh_candidates();
        assert!(
            !candidates.iter().any(|(d, _)| d == "refreshing.test"),
            "Entrada com refreshing=true não deve ser candidata. Candidatos: {:?}",
            candidates
        );
    }

    /// marked_for_deletion → nunca candidato.
    #[test]
    fn test_refresh_excludes_marked_for_deletion() {
        let cache = make_cache_with_window(7200);
        coarse_clock::tick();

        cache.insert(
            "marked.test",
            RecordType::CNAME,
            make_cname("alias"),
            1,
            None,
        );
        let _ = cache.get(&Arc::from("marked.test"), &RecordType::CNAME);

        std::thread::sleep(std::time::Duration::from_secs(2));
        coarse_clock::tick();

        let _ = cache.get(&Arc::from("marked.test"), &RecordType::CNAME);

        let candidates = cache.get_refresh_candidates();
        assert!(
            !candidates.iter().any(|(d, _)| d == "marked.test"),
            "Entrada marcada para deleção não deve ser candidata. Candidatos: {:?}",
            candidates
        );
    }
}
