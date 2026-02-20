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
        let mut candidates = Vec::new();
        let now = coarse_now_secs();

        for entry in self.cache.iter() {
            let record = entry.value();

            // Lazy-deleted entries never get refreshed
            if record.is_marked_for_deletion() {
                continue;
            }

            // Negative responses and HTTPS records are never proactively refreshed
            if record.data.is_negative() {
                continue;
            }

            let key = entry.key();
            if matches!(key.record_type, RecordType::HTTPS) {
                continue;
            }

            let hit_count = record.hit_count.load(AtomicOrdering::Relaxed);
            let last_access = record.last_access.load(AtomicOrdering::Relaxed);
            let age_since_access = now.saturating_sub(last_access);
            let within_window = hit_count > 0 && age_since_access <= self.access_window_secs;

            if !within_window {
                continue;
            }

            if record.is_expired_at_secs(now) {
                if record.is_stale_usable_at_secs(now)
                    && record
                        .refreshing
                        .compare_exchange(
                            false,
                            true,
                            AtomicOrdering::Acquire,
                            AtomicOrdering::Relaxed,
                        )
                        .is_ok()
                {
                    candidates.push((key.domain.clone(), key.record_type));
                }
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            if record
                .refreshing
                .compare_exchange(
                    false,
                    true,
                    AtomicOrdering::Acquire,
                    AtomicOrdering::Relaxed,
                )
                .is_ok()
            {
                candidates.push((key.domain.clone(), key.record_type));
            }
        }

        candidates
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
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
            refresh_threshold: 0.0, // toda entrada qualifica pelo tempo imediatamente
            batch_eviction_percentage: 0.2,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs,
            eviction_sample_size: 8,
        })
    }

    fn make_cname(name: &str) -> CachedData {
        CachedData::CanonicalName(Arc::from(name))
    }

    /// Fix 2: Entrada expirada DENTRO da janela → candidato urgente.
    #[test]
    fn test_refresh_includes_expired_entry_within_window() {
        let cache = make_cache_with_window(7200);
        coarse_clock::tick();

        // TTL=2s → grace period = 2×TTL = 4s. Sleep 3s: expirada mas ainda stale-usable (age=3 < 4).
        cache.insert(
            "expired-window.test",
            RecordType::CNAME,
            make_cname("alias"),
            2,
            None,
        );
        // Registrar hit para entrar na janela
        let _ = cache.get(&Arc::from("expired-window.test"), &RecordType::CNAME);

        // Aguardar expiração do TTL=2s (grace period estende até inserted_at + 4s)
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
        let cache = make_cache_with_window(0); // janela = 0s
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
        // Sem chamada a get() → hit_count = 0

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
        // refresh_threshold=0.0, então qualquer entrada com hit é candidata
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
        use std::sync::atomic::Ordering;

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

        // Simular que já está sendo refreshado
        let key = crate::dns::cache::key::CacheKey::new("refreshing.test", RecordType::CNAME);
        if let Some(entry) = cache.cache.get(&key) {
            entry.refreshing.store(true, Ordering::Relaxed);
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

        // get() após expiração marca para deleção
        let _ = cache.get(&Arc::from("marked.test"), &RecordType::CNAME);

        let candidates = cache.get_refresh_candidates();
        assert!(
            !candidates.iter().any(|(d, _)| d == "marked.test"),
            "Entrada marcada para deleção não deve ser candidata. Candidatos: {:?}",
            candidates
        );
    }
}
