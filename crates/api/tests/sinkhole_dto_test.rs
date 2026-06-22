use ferrous_dns_api::dto::config::{parse_sinkhole_ipv4, parse_sinkhole_ipv6, sinkhole_to_string};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn empty_string_clears_sinkhole() {
    assert_eq!(parse_sinkhole_ipv4("").unwrap(), None);
    assert_eq!(parse_sinkhole_ipv4("   ").unwrap(), None);
    assert_eq!(parse_sinkhole_ipv6("").unwrap(), None);
}

#[test]
fn valid_addresses_parse() {
    assert_eq!(
        parse_sinkhole_ipv4("192.168.1.2").unwrap(),
        Some(Ipv4Addr::new(192, 168, 1, 2))
    );
    assert_eq!(
        parse_sinkhole_ipv6("fd00::2").unwrap(),
        Some("fd00::2".parse::<Ipv6Addr>().unwrap())
    );
}

#[test]
fn invalid_addresses_are_rejected() {
    assert!(parse_sinkhole_ipv4("10.0.0.300").is_err());
    assert!(parse_sinkhole_ipv4("not-an-ip").is_err());
    // Wrong family is rejected too.
    assert!(parse_sinkhole_ipv4("fd00::2").is_err());
    assert!(parse_sinkhole_ipv6("192.168.1.2").is_err());
}

#[test]
fn formatting_round_trips() {
    assert_eq!(sinkhole_to_string(None::<Ipv4Addr>), "");
    assert_eq!(
        sinkhole_to_string(Some(Ipv4Addr::new(192, 168, 1, 2))),
        "192.168.1.2"
    );
    let v6 = "fd00::2".parse::<Ipv6Addr>().unwrap();
    assert_eq!(sinkhole_to_string(Some(v6)), "fd00::2");
}
