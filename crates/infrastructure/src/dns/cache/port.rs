use super::data::{CachedData, CachedDnssecStatus};
use super::key::BorrowedKey;
use ferrous_dns_domain::RecordType;

/// How permanent records at a name apply to the requested record type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalRecordStatus {
    /// No permanent record answers or owns this query.
    NotLocal,
    /// The requested type has a permanent entry, including non-address types.
    Present,
    /// A permanent A/AAAA record owns the name, but this type is not configured.
    MissingType,
}

pub trait DnsCacheAccess: Send + Sync {
    /// A hit's data, DNSSEC status, remaining TTL, and whether the local DNS
    /// server gave the answer, from cache view `view` (0 for the one every
    /// client shares).
    fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
        view: u32,
    ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>, bool)>;

    /// Checks the requested type and name ownership in one lookup.
    fn local_record_status(&self, domain: &str, record_type: &RecordType) -> LocalRecordStatus;

    /// Stores under `key`, in the view it names. `local_dns` marks an answer
    /// from the local DNS server, which its hits report.
    fn insert(
        &self,
        key: BorrowedKey<'_>,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<CachedDnssecStatus>,
        local_dns: bool,
    );

    /// Counts an upstream failure that was deliberately not cached as a
    /// negative answer. A no-op by default so test doubles skip metrics.
    fn record_transient_upstream_error(&self) {}
}
