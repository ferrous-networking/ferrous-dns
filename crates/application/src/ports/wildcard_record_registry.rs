use ferrous_dns_domain::RecordType;
use std::net::IpAddr;

/// Live registry of wildcard local DNS records — `*.home.lan` and the like.
///
/// Implementations keep an in-memory index updated at runtime so that a wildcard
/// added or removed through the admin UI takes effect on the next query, without
/// a server restart. Wildcards deliberately never reach the DNS cache: a cache
/// key is matched exactly, so an expansion could not be invalidated on delete.
pub trait WildcardRecordRegistry: Send + Sync {
    /// Inserts or overwrites the wildcard covering `suffix` — the fully-qualified
    /// name with its leading `*.` removed — for the given record type.
    fn register(&self, suffix: &str, record_type: RecordType, address: IpAddr, ttl: u32);

    /// Removes the wildcard covering `suffix` for `record_type`, if present.
    fn unregister(&self, suffix: &str, record_type: RecordType);
}
