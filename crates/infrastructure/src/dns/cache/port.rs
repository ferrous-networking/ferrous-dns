use super::data::{CachedData, DnssecStatus};
use ferrous_dns_domain::RecordType;

pub trait DnsCacheAccess: Send + Sync {
    fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<DnssecStatus>, Option<u32>)>;

    fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<DnssecStatus>,
    );

    /// Phase 6: records a transient upstream error that was explicitly NOT
    /// cached as a negative response (timeout, connection refused/reset,
    /// no healthy servers, etc.). Default is a no-op so test doubles don't
    /// have to implement metrics.
    #[inline]
    fn record_transient_upstream_error(&self) {}
}
