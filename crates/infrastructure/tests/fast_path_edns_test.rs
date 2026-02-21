use ferrous_dns_infrastructure::dns::fast_path::parse_query;

fn build_a_query(domain: &str) -> Vec<u8> {
    let mut buf = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // flags: RD set
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01, // ARCOUNT = 1 (OPT record)
    ];
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label
    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    buf
}

fn append_opt_record(buf: &mut Vec<u8>, version: u8, do_bit: bool) {
    buf.push(0x00); // NAME = root
    buf.extend_from_slice(&[0x00, 41]); // TYPE = OPT
    buf.extend_from_slice(&[0x10, 0x00]); // CLASS = 4096 (UDP payload size)
    buf.push(0x00); // extended RCODE = 0
    buf.push(version); // EDNS version
    let flags: u16 = if do_bit { 0x8000 } else { 0x0000 };
    buf.extend_from_slice(&flags.to_be_bytes()); // DO + Z flags
    buf.extend_from_slice(&[0x00, 0x00]); // RDLEN = 0
}

#[test]
fn test_edns0_version_zero_accepted() {
    let mut buf = build_a_query("example.com");
    append_opt_record(&mut buf, 0, false);
    let result = parse_query(&buf);
    assert!(
        result.is_some(),
        "version=0 should be accepted on fast path"
    );
}

#[test]
fn test_edns0_version_one_falls_back_to_hickory() {
    let mut buf = build_a_query("example.com");
    append_opt_record(&mut buf, 1, false);
    let result = parse_query(&buf);
    assert!(
        result.is_none(),
        "version=1 should fall back (Hickory handles BADVERS)"
    );
}

#[test]
fn test_edns0_version_255_falls_back_to_hickory() {
    let mut buf = build_a_query("example.com");
    append_opt_record(&mut buf, 255, false);
    let result = parse_query(&buf);
    assert!(result.is_none(), "version=255 should fall back");
}

#[test]
fn test_query_without_edns_accepted() {
    let mut buf = vec![
        0x12, 0x34, 0x01, 0x00, // ID + flags
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QDCOUNT=1 ARCOUNT=0
    ];
    buf.push(7);
    buf.extend_from_slice(b"example");
    buf.push(3);
    buf.extend_from_slice(b"com");
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    let result = parse_query(&buf);
    assert!(result.is_some(), "query without OPT should be accepted");
}
