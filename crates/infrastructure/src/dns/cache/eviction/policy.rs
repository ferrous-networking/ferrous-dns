use crate::dns::cache::record::CachedRecord;

/// Trait de política de eviction para o cache DNS.
///
/// Score alto = entrada valiosa (sobrevive ao eviction).
/// Score negativo = abaixo do mínimo configurado (prioritário para remoção).
///
/// Implementado por cada estratégia em seu próprio módulo.
/// O dispatch é feito via [`ActiveEvictionPolicy`] sem vtable (zero-cost).
pub trait EvictionPolicy: Send + Sync {
    /// Calcula o score de eviction para uma entrada.
    ///
    /// `now_secs` é o timestamp coarse atual, passado para evitar chamadas
    /// redundantes ao relógio em loops de eviction.
    fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64;
}
