//! UDP wire-data fast path: the client's advertised EDNS buffer must be
//! honored, so an oversized cached answer is deferred to the slow path (which
//! truncates with TC=1) rather than served verbatim. These cover the two halves
//! that feed that decision: `wire_fits_udp_buffer` (the check) and
//! `parse_query`'s `client_max_size` extraction (its input).

use ferrous_dns_infrastructure::dns::fast_path::parse_query;
use ferrous_dns_infrastructure::dns::wire_response::wire_fits_udp_buffer;

// ── wire_fits_udp_buffer ────────────────────────────────────────────────────

#[test]
fn fits_when_smaller_than_buffer() {
    assert!(wire_fits_udp_buffer(400, 512));
    assert!(wire_fits_udp_buffer(1000, 4096));
}

#[test]
fn fits_at_exact_buffer_size() {
    assert!(wire_fits_udp_buffer(512, 512));
    assert!(wire_fits_udp_buffer(4096, 4096));
}

#[test]
fn defers_when_larger_than_buffer() {
    assert!(!wire_fits_udp_buffer(513, 512));
    assert!(!wire_fits_udp_buffer(4097, 4096));
}

#[test]
fn defers_just_over_the_512_floor() {
    // A no-EDNS / sub-512 client is floored to 512 by parse_query; a 513-byte
    // cached answer must not be served verbatim.
    assert!(!wire_fits_udp_buffer(513, 512));
}

// ── parse_query: client_max_size extraction ─────────────────────────────────

fn build_a_query_with_arcount(domain: &str, arcount: u16) -> Vec<u8> {
    let mut buf = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // flags: RD set
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
    ];
    buf.extend_from_slice(&arcount.to_be_bytes()); // ARCOUNT
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label
    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    buf
}

/// Appends an EDNS0 OPT record advertising `udp_payload` as the client buffer.
fn append_opt_record(buf: &mut Vec<u8>, udp_payload: u16) {
    buf.push(0x00); // NAME = root
    buf.extend_from_slice(&[0x00, 41]); // TYPE = OPT
    buf.extend_from_slice(&udp_payload.to_be_bytes()); // CLASS = UDP payload size
    buf.push(0x00); // extended RCODE = 0
    buf.push(0x00); // EDNS version = 0
    buf.extend_from_slice(&[0x00, 0x00]); // DO + Z flags
    buf.extend_from_slice(&[0x00, 0x00]); // RDLEN = 0
}

#[test]
fn client_max_size_reflects_advertised_buffer() {
    let mut buf = build_a_query_with_arcount("example.com", 1);
    append_opt_record(&mut buf, 4096);
    let q = parse_query(&buf).expect("valid EDNS query");
    assert_eq!(q.client_max_size, 4096);
    assert!(q.has_edns);
}

#[test]
fn client_max_size_floored_at_512() {
    // RFC 6891 §6.2.3: advertised values below 512 are treated as 512.
    let mut buf = build_a_query_with_arcount("example.com", 1);
    append_opt_record(&mut buf, 200);
    let q = parse_query(&buf).expect("valid EDNS query");
    assert_eq!(q.client_max_size, 512);
}

#[test]
fn client_max_size_defaults_to_512_without_edns() {
    let buf = build_a_query_with_arcount("example.com", 0);
    let q = parse_query(&buf).expect("valid non-EDNS query");
    assert_eq!(q.client_max_size, 512);
    assert!(!q.has_edns);
}
