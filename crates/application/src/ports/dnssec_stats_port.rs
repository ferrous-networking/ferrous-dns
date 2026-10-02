/// Live counters from the DNSSEC validator's DNSKEY/DS cache.
///
/// Process-lifetime totals, not windowed: unlike the query-log-derived DNSSEC
/// stats they are not scoped to a reporting period.
#[derive(Debug, Clone, Default)]
pub struct DnssecValidatorStats {
    pub dnskey_entries: usize,
    pub ds_entries: usize,
    pub dnskey_hits: u64,
    pub dnskey_misses: u64,
    pub ds_hits: u64,
    pub ds_misses: u64,
    /// Empty DS answers that carried no authenticated NSEC/NSEC3 denial and so
    /// failed validation. A non-trivial count means the configured upstreams
    /// strip DNSSEC proofs; Strict mode SERVFAILs the affected names.
    pub ds_denials_unproven: u64,
}

/// Port for reading the DNSSEC validator's cache counters.
pub trait DnssecStatsPort: Send + Sync {
    fn validator_stats(&self) -> DnssecValidatorStats;
}
