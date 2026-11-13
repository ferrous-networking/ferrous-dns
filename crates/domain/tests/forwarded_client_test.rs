use ferrous_dns_domain::forwarded_client_ip;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn nets(list: &[&str]) -> Vec<IpNetwork> {
    list.iter().map(|net| net.parse().unwrap()).collect()
}

#[test]
fn test_untrusted_peer_cannot_name_a_client() {
    let client = forwarded_client_ip(
        ip("198.51.100.7"),
        ["203.0.113.9"].into_iter(),
        Some("203.0.113.10"),
        &nets(&["127.0.0.0/8"]),
    );
    assert_eq!(client, ip("198.51.100.7"));
}

#[test]
fn test_no_trusted_proxies_means_the_peer() {
    let client = forwarded_client_ip(ip("127.0.0.1"), ["203.0.113.9"].into_iter(), None, &[]);
    assert_eq!(client, ip("127.0.0.1"));
}

#[test]
fn test_chain_is_walked_past_trusted_hops_to_the_client() {
    let client = forwarded_client_ip(
        ip("127.0.0.1"),
        ["1.1.1.1, 203.0.113.9, 10.0.0.2"].into_iter(),
        None,
        &nets(&["127.0.0.0/8", "10.0.0.0/8"]),
    );
    // 1.1.1.1 was written by the client itself, left of the first untrusted hop.
    assert_eq!(client, ip("203.0.113.9"));
}

#[test]
fn test_repeated_headers_are_read_in_order() {
    let client = forwarded_client_ip(
        ip("127.0.0.1"),
        ["203.0.113.9", "10.0.0.2"].into_iter(),
        None,
        &nets(&["127.0.0.0/8", "10.0.0.0/8"]),
    );
    assert_eq!(client, ip("203.0.113.9"));
}

#[test]
fn test_a_garbled_hop_ends_the_chain() {
    let client = forwarded_client_ip(
        ip("127.0.0.1"),
        ["203.0.113.9, not-an-ip, 10.0.0.2"].into_iter(),
        None,
        &nets(&["127.0.0.0/8", "10.0.0.0/8"]),
    );
    assert_eq!(client, ip("10.0.0.2"));
}

#[test]
fn test_real_ip_counts_only_without_forwarded_for() {
    let trusted = nets(&["127.0.0.0/8"]);
    let alone = forwarded_client_ip(
        ip("127.0.0.1"),
        std::iter::empty(),
        Some("203.0.113.10"),
        &trusted,
    );
    assert_eq!(alone, ip("203.0.113.10"));

    let beside = forwarded_client_ip(
        ip("127.0.0.1"),
        ["203.0.113.9"].into_iter(),
        Some("203.0.113.10"),
        &trusted,
    );
    assert_eq!(beside, ip("203.0.113.9"));
}

#[test]
fn test_ports_and_mapped_addresses_are_normalized() {
    let trusted = nets(&["127.0.0.0/8"]);
    let client = forwarded_client_ip(
        ip("::ffff:127.0.0.1"),
        ["[2001:db8::1]:4711"].into_iter(),
        None,
        &trusted,
    );
    assert_eq!(client, ip("2001:db8::1"));

    let mapped = forwarded_client_ip(
        ip("127.0.0.1"),
        ["::ffff:203.0.113.9"].into_iter(),
        None,
        &trusted,
    );
    assert_eq!(mapped, ip("203.0.113.9"));
}
