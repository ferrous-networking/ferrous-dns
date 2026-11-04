#![allow(dead_code)]

//! What the cache fast-path tests share: `respond` closures that serve every
//! hit, and resolvers whose cache already holds an answer, as it does once any
//! client resolved the name (the cache is shared across groups).

use super::MockDnsResolver;
use ferrous_dns_application::ports::DnsResolution;
use std::net::IpAddr;

/// A fast-path `respond` that serves every A/AAAA hit.
pub fn served(
    addresses: &[IpAddr],
    ttl: u32,
    _cookie: Option<&[u8]>,
) -> Option<(Vec<IpAddr>, u32)> {
    Some((addresses.to_vec(), ttl))
}

/// A fast-path `respond` that serves every wire hit.
pub fn served_wire(wire: &[u8], remaining: u32, _cookie: Option<&[u8]>) -> Option<(Vec<u8>, u32)> {
    Some((wire.to_vec(), remaining))
}

/// A resolver whose cache answers `domain` with the address `ip`.
pub fn resolver_with_cached_ip(domain: &str, ip: &str) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver.set_cached_response(domain, DnsResolution::new(vec![ip.parse().unwrap()], true));
    resolver
}

/// A resolver whose cache answers `domain` with an upstream wire answer.
pub fn resolver_with_cached_wire(domain: &str) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver.set_cached_response(
        domain,
        DnsResolution {
            upstream_wire_data: Some(bytes::Bytes::from_static(b"\x00\x01\x02\x03")),
            min_ttl: Some(300),
            ..DnsResolution::new(vec![], true)
        },
    );
    resolver
}
