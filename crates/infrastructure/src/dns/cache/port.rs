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
}
