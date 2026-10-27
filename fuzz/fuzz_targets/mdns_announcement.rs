//! mDNS announcement parser. With `dns.mdns_enabled` on, every datagram any
//! device on the LAN multicasts to 224.0.0.251:5353 reaches it, and what it
//! returns becomes a client's name in the dashboard and the query log.
//!
//! Beyond not panicking: a device only ever names itself, so any name comes
//! with at least one pair for the datagram's source, and every name is fit to
//! show.
#![no_main]

use ferrous_dns_infrastructure::system::hostnames_from_mdns;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let names = hostnames_from_mdns(data, source);

    assert!(names.is_empty() || names.iter().any(|(ip, _)| *ip == source));
    for (_, name) in &names {
        assert!(!name.is_empty() && name.len() <= 253);
        assert!(!name.chars().any(|c| c.is_control() || c == '\\'));
    }
});
