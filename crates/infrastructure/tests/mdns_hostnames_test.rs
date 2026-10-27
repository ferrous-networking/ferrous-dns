//! Client names read from mDNS announcements. A device names only itself:
//! a `.local` host name counts when one of its A or AAAA records holds the
//! datagram's source address, and then its other addresses count too.

use ferrous_dns_infrastructure::system::hostnames_from_mdns;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
const IN: u16 = 1;
/// The class an mDNS responder sends: IN with the cache-flush bit set.
const IN_FLUSH: u16 = 0x8001;
const CH: u16 = 3;
const TTL: u32 = 120;

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn record(owner: &str, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut out = encode_name(owner);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn a(owner: &str, ip: Ipv4Addr) -> Vec<u8> {
    record(owner, 1, IN_FLUSH, TTL, &ip.octets())
}

fn aaaa(owner: &str, ip: Ipv6Addr) -> Vec<u8> {
    record(owner, 28, IN_FLUSH, TTL, &ip.octets())
}

/// A datagram with the QR bit as given and no question.
fn datagram(response: bool, answers: &[Vec<u8>], additionals: &[Vec<u8>]) -> Vec<u8> {
    let flags: u16 = if response { 0x8400 } else { 0 };
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(additionals.len() as u16).to_be_bytes());
    for rr in answers.iter().chain(additionals) {
        out.extend_from_slice(rr);
    }
    out
}

fn response(answers: &[Vec<u8>]) -> Vec<u8> {
    datagram(true, answers, &[])
}

fn names(packet: &[u8]) -> Vec<(IpAddr, Arc<str>)> {
    hostnames_from_mdns(packet, IpAddr::V4(SOURCE))
}

fn named(ip: impl Into<IpAddr>, name: &str) -> (IpAddr, Arc<str>) {
    (ip.into(), Arc::from(name))
}

#[test]
fn a_device_announcing_itself_is_named_with_all_its_addresses() {
    let v6_link: Ipv6Addr = "fe80::1c2d:3e4f:5a6b:7c8d".parse().unwrap();
    let v6_global: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let packet = datagram(
        true,
        &[a("iPhone-de-Ana.local", SOURCE)],
        &[
            aaaa("iPhone-de-Ana.local", v6_link),
            aaaa("iPhone-de-Ana.local", v6_global),
        ],
    );

    assert_eq!(
        names(&packet),
        vec![
            named(SOURCE, "iPhone-de-Ana"),
            named(v6_link, "iPhone-de-Ana"),
            named(v6_global, "iPhone-de-Ana"),
        ]
    );
}

#[test]
fn the_class_without_the_cache_flush_bit_counts_too() {
    let packet = response(&[record("printer.local", 1, IN, TTL, &SOURCE.octets())]);

    assert_eq!(names(&packet), vec![named(SOURCE, "printer")]);
}

#[test]
fn a_device_cannot_name_another_address() {
    let other = Ipv4Addr::new(192, 168, 1, 30);
    let packet = response(&[a("HP-LaserJet.local", other)]);

    assert!(names(&packet).is_empty());
}

/// A Bonjour sleep proxy answers for the machines it covers; only its own
/// name is taken from such a datagram.
#[test]
fn only_the_senders_own_name_is_taken_from_a_mixed_datagram() {
    let sleeping = Ipv4Addr::new(192, 168, 1, 40);
    let packet = response(&[a("AppleTV.local", SOURCE), a("MacBook-Pro.local", sleeping)]);

    assert_eq!(names(&packet), vec![named(SOURCE, "AppleTV")]);
}

#[test]
fn an_aaaa_record_alone_does_not_vouch_for_an_ipv4_sender() {
    let packet = response(&[aaaa("iPhone.local", "2001:db8::20".parse().unwrap())]);

    assert!(names(&packet).is_empty());
}

/// A query's known-answer section lists records the asker already holds,
/// about other devices.
#[test]
fn a_query_names_nobody() {
    let packet = datagram(false, &[a("iPhone.local", SOURCE)], &[]);

    assert!(names(&packet).is_empty());
}

#[test]
fn a_goodbye_names_nobody() {
    let packet = response(&[record("iPhone.local", 1, IN_FLUSH, 0, &SOURCE.octets())]);

    assert!(names(&packet).is_empty());
}

#[test]
fn only_names_under_local_count() {
    for owner in ["iPhone.example", "iPhone.local.example", "local"] {
        let packet = response(&[a(owner, SOURCE)]);
        assert!(names(&packet).is_empty(), "{owner}");
    }
}

#[test]
fn a_record_in_another_class_does_not_count() {
    let packet = response(&[record("iPhone.local", 1, CH, TTL, &SOURCE.octets())]);

    assert!(names(&packet).is_empty());
}

#[test]
fn the_name_keeps_its_case_and_drops_local_in_any_case() {
    let packet = response(&[a("Anas-MacBook-Pro.LOCAL", SOURCE)]);

    assert_eq!(names(&packet), vec![named(SOURCE, "Anas-MacBook-Pro")]);
}

#[test]
fn a_name_with_control_characters_is_not_shown() {
    let packet = response(&[a("bell\u{7}.local", SOURCE)]);

    assert!(names(&packet).is_empty());
}

#[test]
fn the_same_address_and_name_are_reported_once() {
    let packet = datagram(
        true,
        &[a("iPhone.local", SOURCE)],
        &[a("iphone.local", SOURCE)],
    );

    assert_eq!(names(&packet), vec![named(SOURCE, "iPhone")]);
}

/// A device that announces two host names for its address (after an mDNS
/// name conflict, say) is named once, after the first, with only that
/// name's addresses.
#[test]
fn a_device_is_named_after_the_first_name_it_announces() {
    let v6_first: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let v6_second: Ipv6Addr = "2001:db8::21".parse().unwrap();
    let packet = datagram(
        true,
        &[a("iPhone.local", SOURCE), a("iPhone-2.local", SOURCE)],
        &[
            aaaa("iPhone-2.local", v6_second),
            aaaa("iPhone.local", v6_first),
        ],
    );

    assert_eq!(
        names(&packet),
        vec![named(SOURCE, "iPhone"), named(v6_first, "iPhone")]
    );
}

#[test]
fn other_records_are_ignored() {
    let ptr_rdata = encode_name("iPhone._companion-link._tcp.local");
    let packet = response(&[
        record("_companion-link._tcp.local", 12, IN, 4500, &ptr_rdata),
        a("iPhone.local", SOURCE),
    ]);

    assert_eq!(names(&packet), vec![named(SOURCE, "iPhone")]);
}

/// The fuzz target's seeds, run on stable: only the datagrams that announce
/// their sender name it.
#[test]
fn the_fuzz_seeds_name_only_their_sender() {
    let corpus = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/mdns_announcement"
    );
    let mut naming: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(corpus).unwrap() {
        let path = entry.unwrap().path();
        let found = names(&std::fs::read(&path).unwrap());
        if !found.is_empty() {
            assert!(found.iter().all(|(_, name)| &**name == "iPhone-de-Ana"));
            naming.push(path.file_stem().unwrap().to_string_lossy().into_owned());
        }
    }
    naming.sort();

    assert_eq!(naming, ["self_announcement_a_aaaa", "service_with_host"]);
}

#[test]
fn malformed_datagrams_name_nobody() {
    let whole = response(&[a("iPhone.local", SOURCE)]);
    let cases: [&[u8]; 4] = [
        &[],
        &[0xff; 11],
        &whole[..whole.len() - 3],
        b"not a dns message at all, just bytes",
    ];
    for packet in cases {
        assert!(names(packet).is_empty(), "{packet:?}");
    }
}
