use super::coarse_clock::coarse_now_secs;
use super::storage::DnsCache;
use ferrous_dns_domain::RecordType;
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    /// Retorna entradas candidatas ao refresh otimista.
    ///
    /// Uma entrada é candidata se:
    /// - Não está expirada nem marcada para deleção
    /// - Não é uma resposta negativa nem do tipo HTTPS
    /// - Passou pelo threshold de tempo (ex.: 75% do TTL decorrido)
    /// - Teve pelo menos 1 hit real no cache L2
    /// - O último acesso ocorreu dentro da janela configurável (`access_window_secs`)
    pub fn get_refresh_candidates(&self) -> Vec<(String, RecordType)> {
        let mut candidates = Vec::new();
        let now = coarse_now_secs();

        for entry in self.cache.iter() {
            let record = entry.value();

            if record.is_expired() || record.is_marked_for_deletion() {
                continue;
            }

            if record.data.is_negative() {
                continue;
            }

            let key = entry.key();
            if matches!(key.record_type, RecordType::HTTPS) {
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            let hit_count = record.hit_count.load(AtomicOrdering::Relaxed);
            let last_access = record.last_access.load(AtomicOrdering::Relaxed);
            let age_since_access = now.saturating_sub(last_access);

            if hit_count > 0 && age_since_access <= self.access_window_secs {
                candidates.push((key.domain.to_string(), key.record_type));
            }
        }

        candidates
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;

        let key = CacheKey::from_str(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
        }
    }
}
