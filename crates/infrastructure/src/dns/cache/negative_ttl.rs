use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tracker de frequência de queries para domínios com respostas negativas.
///
/// **FASE 3**: TTL dinâmico baseado em frequência de queries.
/// Domínios frequentemente consultados (que não existem) recebem TTL menor (60s)
/// para evitar cache pollution, enquanto domínios raros recebem TTL maior (300s).
pub struct NegativeQueryTracker {
    /// Contador de queries por domínio (últimos 5 minutos)
    query_counts: Arc<DashMap<Arc<str>, QueryCounter>>,

    /// TTL curto para domínios frequentes (60s)
    frequent_ttl: u32,

    /// TTL longo para domínios raros (300s)
    rare_ttl: u32,

    /// Threshold de queries para considerar "frequente" (5 queries em 5min)
    frequency_threshold: u32,
}

struct QueryCounter {
    count: AtomicU64,
    last_reset: Instant,
}

impl NegativeQueryTracker {
    /// Cria novo tracker com configurações default.
    ///
    /// Default:
    /// - TTL frequente: 60s (domínios consultados >5x em 5min)
    /// - TTL raro: 300s (domínios consultados <=5x em 5min)
    /// - Threshold: 5 queries em 5 minutos
    pub fn new() -> Self {
        Self {
            query_counts: Arc::new(DashMap::new()),
            frequent_ttl: 60,
            rare_ttl: 300,
            frequency_threshold: 5,
        }
    }

    /// Cria tracker com configurações customizadas.
    pub fn with_config(frequent_ttl: u32, rare_ttl: u32, frequency_threshold: u32) -> Self {
        Self {
            query_counts: Arc::new(DashMap::new()),
            frequent_ttl,
            rare_ttl,
            frequency_threshold,
        }
    }

    /// Registra query para domínio negativo e retorna TTL apropriado.
    ///
    /// # Lógica
    /// - Domínio frequente (>5 queries/5min): TTL = 60s (cache curto)
    /// - Domínio raro (<=5 queries/5min): TTL = 300s (cache longo)
    ///
    /// # Exemplo
    /// ```rust,ignore
    /// let tracker = NegativeQueryTracker::new();
    /// let ttl = tracker.record_and_get_ttl("nonexistent.example.com");
    /// // Primeira query: ttl = 300s (raro)
    /// // 6ª query em 5min: ttl = 60s (frequente)
    /// ```
    pub fn record_and_get_ttl(&self, domain: &str) -> u32 {
        let domain_arc: Arc<str> = Arc::from(domain);

        let mut entry = self
            .query_counts
            .entry(domain_arc.clone())
            .or_insert_with(|| QueryCounter {
                count: AtomicU64::new(0),
                last_reset: Instant::now(),
            });

        let counter = entry.value();

        // Reset contador se passou 5 minutos
        if counter.last_reset.elapsed() > Duration::from_secs(300) {
            // Criar novo counter
            *entry.value_mut() = QueryCounter {
                count: AtomicU64::new(1),
                last_reset: Instant::now(),
            };
            return self.rare_ttl; // Primeira query após reset = raro
        }

        // Incrementa contador
        let count = counter.count.fetch_add(1, Ordering::Relaxed) + 1;

        // Decide TTL baseado na frequência
        if count > self.frequency_threshold as u64 {
            // Domínio frequente (potencial spam/typo) - TTL curto
            self.frequent_ttl
        } else {
            // Domínio raro - TTL longo
            self.rare_ttl
        }
    }

    /// Retorna estatísticas do tracker.
    pub fn stats(&self) -> TrackerStats {
        let mut frequent_domains = 0;
        let mut rare_domains = 0;

        for entry in self.query_counts.iter() {
            let count = entry.value().count.load(Ordering::Relaxed);
            if count > self.frequency_threshold as u64 {
                frequent_domains += 1;
            } else {
                rare_domains += 1;
            }
        }

        TrackerStats {
            total_domains: self.query_counts.len(),
            frequent_domains,
            rare_domains,
            frequent_ttl: self.frequent_ttl,
            rare_ttl: self.rare_ttl,
        }
    }

    /// Limpa entradas antigas (>5 minutos sem atividade).
    pub fn cleanup_old_entries(&self) -> usize {
        let mut removed = 0;

        self.query_counts.retain(|_domain, counter| {
            if counter.last_reset.elapsed() > Duration::from_secs(300) {
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }
}

impl Default for NegativeQueryTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Estatísticas do tracker de queries negativas.
#[derive(Debug, Clone)]
pub struct TrackerStats {
    /// Total de domínios rastreados
    pub total_domains: usize,
    /// Domínios frequentes (TTL curto)
    pub frequent_domains: usize,
    /// Domínios raros (TTL longo)
    pub rare_domains: usize,
    /// TTL usado para frequentes
    pub frequent_ttl: u32,
    /// TTL usado para raros
    pub rare_ttl: u32,
}
