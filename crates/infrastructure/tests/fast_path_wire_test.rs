use ferrous_dns_infrastructure::dns::fast_path::{parse_query, FastPathKind};

fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = vec![
        0xAB, 0xCD, // ID
        0x01, 0x00, // flags: RD set
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ];
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label
    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    buf
}

#[test]
fn mx_query_parses_as_wire_data() {
    let buf = build_query("example.com", 15);
    let q = parse_query(&buf).expect("MX query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::WireData));
    assert_eq!(q.domain(), "example.com");
}

#[test]
fn txt_query_parses_as_wire_data() {
    let buf = build_query("example.com", 16);
    let q = parse_query(&buf).expect("TXT query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::WireData));
}

#[test]
fn ns_query_parses_as_wire_data() {
    let buf = build_query("example.com", 2);
    let q = parse_query(&buf).expect("NS query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::WireData));
}

#[test]
fn cname_query_parses_as_wire_data() {
    let buf = build_query("www.example.com", 5);
    let q = parse_query(&buf).expect("CNAME query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::WireData));
    assert_eq!(q.domain(), "www.example.com");
}

#[test]
fn soa_query_parses_as_wire_data() {
    let buf = build_query("example.com", 6);
    let q = parse_query(&buf).expect("SOA query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::WireData));
}

#[test]
fn ptr_query_parses_as_wire_data() {
    let buf = build_query("1.0.0.127.in-addr.arpa", 12);
    let q = parse_query(&buf).expect("PTR query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::WireData));
}

#[test]
fn a_query_parses_as_ip_address() {
    let buf = build_query("example.com", 1);
    let q = parse_query(&buf).expect("A query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::IpAddress));
}

#[test]
fn aaaa_query_parses_as_ip_address() {
    let buf = build_query("example.com", 28);
    let q = parse_query(&buf).expect("AAAA query should be accepted on fast path");
    assert!(matches!(q.kind, FastPathKind::IpAddress));
}

#[test]
fn unknown_qtype_returns_none() {
    let buf = build_query("example.com", 255);
    assert!(
        parse_query(&buf).is_none(),
        "unknown qtype should fall back to slow path"
    );
}
