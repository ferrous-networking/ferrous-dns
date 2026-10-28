//! mDNS announcement parser. With `dns.mdns_enabled` on, every datagram any
//! device on the LAN multicasts to 224.0.0.251:5353 reaches it, and what it
//! returns becomes a client's name in the dashboard and the query log.
//!
//! Beyond not panicking: a device only ever names itself, once, so a datagram
//! yields one name, with at least one pair for the datagram's source, and the
//! name is fit to show.
#![no_main]

use ferrous_dns_infrastructure::system::hostnames_from_mdns;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let names = hostnames_from_mdns(data, source);

    let Some((_, first)) = names.first() else {
        return;
    };
    assert!(
        names.iter().any(|(ip, _)| *ip == source),
        "a name without a pair for the source: {names:?}"
    );
    assert!(
        names.iter().all(|(_, name)| name == first),
        "more than one name in one datagram: {names:?}"
    );
    assert!(
        !first.is_empty() && first.len() <= 253,
        "a name of {} bytes: {first:?}",
        first.len()
    );
    assert!(
        !first.chars().any(|c| c.is_control() || c == '\\'),
        "a name unfit to show: {first:?}"
    );
});
