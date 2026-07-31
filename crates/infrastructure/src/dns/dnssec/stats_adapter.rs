use super::cache::DnssecCache;
use ferrous_dns_application::ports::{DnssecStatsPort, DnssecValidatorStats};
use std::sync::Arc;

/// Exposes the DNSSEC validator's cache counters to the API layer.
///
/// The cache is absent when DNSSEC validation is off; reporting zeros keeps the
/// port total, so callers never have to special-case a missing validator.
pub struct DnssecStatsAdapter {
    cache: Option<Arc<DnssecCache>>,
}

impl DnssecStatsAdapter {
    pub fn new(cache: Arc<DnssecCache>) -> Self {
        Self { cache: Some(cache) }
    }

    pub fn disabled() -> Self {
        Self { cache: None }
    }
}

impl DnssecStatsPort for DnssecStatsAdapter {
    fn validator_stats(&self) -> DnssecValidatorStats {
        let Some(cache) = &self.cache else {
            return DnssecValidatorStats::default();
        };

        let snapshot = cache.stats();
        DnssecValidatorStats {
            dnskey_entries: snapshot.dnskey_entries,
            ds_entries: snapshot.ds_entries,
            dnskey_hits: snapshot.total_dnskey_hits,
            dnskey_misses: snapshot.total_dnskey_misses,
            ds_hits: snapshot.total_ds_hits,
            ds_misses: snapshot.total_ds_misses,
            ds_denial_fail_opens: snapshot.total_ds_denial_fail_opens,
        }
    }
}
