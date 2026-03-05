use std::net::IpAddr;
use std::sync::Arc;

/// Live registry of IP address → PTR hostname mappings derived from local DNS records.
///
/// Implementations keep an in-memory map updated at runtime so that PTR queries are
/// answered instantly without upstream forwarding.
pub trait PtrRecordRegistry: Send + Sync {
    /// Inserts or overwrites the PTR mapping for `ip` with the given fully-qualified
    /// domain name and TTL.
    fn register(&self, ip: IpAddr, fqdn: Arc<str>, ttl: u32);

    /// Removes the PTR mapping for `ip`, if present.
    fn unregister(&self, ip: IpAddr);
}
