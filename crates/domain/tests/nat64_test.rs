use ferrous_dns_domain::{Nat64Prefix, PrivateIpFilter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// The well-known NAT64 prefix network address (`64:ff9b::/96`, last 32 bits 0).
fn well_known() -> Ipv6Addr {
    Ipv6Addr::from_str("64:ff9b::").unwrap()
}

#[test]
fn synthesize_embeds_ipv4_in_last_32_bits() {
    let v4 = Ipv4Addr::new(93, 184, 216, 34);
    let synth = Nat64Prefix::synthesize(well_known(), v4);
    // 93.184.216.34 == 0x5db8d822 -> 64:ff9b::5db8:d822
    assert_eq!(synth, Ipv6Addr::from_str("64:ff9b::5db8:d822").unwrap());
}

#[test]
fn synthesize_overwrites_any_trailing_bits_in_prefix() {
    // A prefix that erroneously carries data in the last 32 bits is masked off
    // by synthesis (the IPv4 fully replaces those bytes).
    let dirty_prefix = Ipv6Addr::from_str("64:ff9b::dead:beef").unwrap();
    let v4 = Ipv4Addr::new(1, 2, 3, 4);
    assert_eq!(
        Nat64Prefix::synthesize(dirty_prefix, v4),
        Ipv6Addr::from_str("64:ff9b::102:304").unwrap()
    );
}

#[test]
fn extract_v4_round_trips_synthesis() {
    let prefix = well_known();
    for v4 in [
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(255, 255, 255, 255),
        Ipv4Addr::new(0, 0, 0, 0),
    ] {
        let synth = Nat64Prefix::synthesize(prefix, v4);
        assert!(Nat64Prefix::contains(prefix, synth));
        assert_eq!(Nat64Prefix::extract_v4(prefix, synth), Some(v4));
    }
}

#[test]
fn extract_v4_rejects_out_of_prefix_address() {
    let prefix = well_known();
    let outside = Ipv6Addr::from_str("2001:db8::1").unwrap();
    assert!(!Nat64Prefix::contains(prefix, outside));
    assert_eq!(Nat64Prefix::extract_v4(prefix, outside), None);
}

#[test]
fn custom_prefix_is_honoured() {
    let prefix = Ipv6Addr::from_str("fd00:64::").unwrap();
    let v4 = Ipv4Addr::new(10, 0, 0, 5);
    let synth = Nat64Prefix::synthesize(prefix, v4);
    assert_eq!(synth, Ipv6Addr::from_str("fd00:64::a00:5").unwrap());
    assert_eq!(Nat64Prefix::extract_v4(prefix, synth), Some(v4));
    // Not contained by the well-known prefix.
    assert!(!Nat64Prefix::contains(well_known(), synth));
}

#[test]
fn ip6_arpa_name_parses_back_to_embedded_address() {
    // Reverse path relies on PrivateIpFilter::extract_ip_from_ptr to recover the
    // Ipv6Addr from an ip6.arpa name, then Nat64Prefix::extract_v4 to get the v4.
    let prefix = well_known();
    let v4 = Ipv4Addr::new(93, 184, 216, 34);
    let synth = Nat64Prefix::synthesize(prefix, v4);
    // 64:ff9b::5db8:d822 reversed nibbles under ip6.arpa.
    let arpa = "2.2.8.d.8.b.d.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa";
    let recovered = PrivateIpFilter::extract_ip_from_ptr(arpa);
    assert_eq!(recovered, Some(IpAddr::V6(synth)));
    if let Some(IpAddr::V6(v6)) = recovered {
        assert_eq!(Nat64Prefix::extract_v4(prefix, v6), Some(v4));
    }
}
