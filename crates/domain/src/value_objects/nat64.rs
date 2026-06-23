use std::net::{Ipv4Addr, Ipv6Addr};

/// NAT64 address arithmetic for DNS64 (RFC 6147 / RFC 6052).
///
/// Only the well-known `/96` prefix length is supported: the IPv4 address
/// occupies the last 32 bits of the IPv6 address and the upper 96 bits come from
/// the configured NAT64 prefix.
pub struct Nat64Prefix;

impl Nat64Prefix {
    /// Synthesizes an AAAA address by embedding `v4` into the last 32 bits of the
    /// `/96` NAT64 `prefix` (RFC 6052 §2.2). `prefix` is expected to be a network
    /// address (last 32 bits zero); they are overwritten regardless.
    pub fn synthesize(prefix: Ipv6Addr, v4: Ipv4Addr) -> Ipv6Addr {
        let mut octets = prefix.octets();
        octets[12..16].copy_from_slice(&v4.octets());
        Ipv6Addr::from(octets)
    }

    /// Returns `true` when `addr` falls within the `/96` NAT64 `prefix` (the
    /// first 96 bits match).
    pub fn contains(prefix: Ipv6Addr, addr: Ipv6Addr) -> bool {
        prefix.octets()[..12] == addr.octets()[..12]
    }

    /// Extracts the embedded IPv4 from a NAT64 address, or `None` when `addr`
    /// is outside the `/96` `prefix`.
    pub fn extract_v4(prefix: Ipv6Addr, addr: Ipv6Addr) -> Option<Ipv4Addr> {
        if !Self::contains(prefix, addr) {
            return None;
        }
        let o = addr.octets();
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    }
}
