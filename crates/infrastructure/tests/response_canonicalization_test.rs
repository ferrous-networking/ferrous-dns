//! Regression: canonicalization must strip 0x20 case from *every* owner name in
//! the raw upstream wire, not just the question.
//!
//! `raw_bytes` is what the cache stores and what the wire fast path replays to
//! clients verbatim, so any randomized case left in it reaches the client. Owner
//! names in the answer section are usually compression pointers back to the
//! question, which made a question-only pass look correct — but an upstream may
//! write them literally, and past offset 16383 a 14-bit compression pointer
//! cannot reach at all, so a large DNSKEY/RRSIG/TXT answer must write them
//! literally. These tests hand-build the wire because hickory's encoder always
//! compresses and so cannot produce the shape being guarded against.

use bytes::Bytes;
use ferrous_dns_infrastructure::dns::forwarding::{ResponseParser, ResponseValidator};
use hickory_proto::rr::RecordType as HRecordType;

const QNAME_LABELS: [&str; 3] = ["WwW", "ExAmPlE", "CoM"];

fn encode_name(name: &[&str], out: &mut Vec<u8>) {
    for label in name {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// One A answer whose owner name is written out literally instead of as a
/// pointer to the question — exactly what a non-compressing upstream sends.
fn uncompressed_response() -> Bytes {
    let mut wire = Vec::new();
    wire.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    wire.extend_from_slice(&0x8180u16.to_be_bytes()); // qr, rd, ra
    wire.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    wire.extend_from_slice(&1u16.to_be_bytes()); // ancount
    wire.extend_from_slice(&0u16.to_be_bytes()); // nscount
    wire.extend_from_slice(&0u16.to_be_bytes()); // arcount

    encode_name(&QNAME_LABELS, &mut wire);
    wire.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    wire.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

    encode_name(&QNAME_LABELS, &mut wire); // literal owner, NOT a pointer
    wire.extend_from_slice(&1u16.to_be_bytes()); // type A
    wire.extend_from_slice(&1u16.to_be_bytes()); // class IN
    wire.extend_from_slice(&60u32.to_be_bytes()); // ttl
    wire.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    wire.extend_from_slice(&[203, 0, 113, 7]); // rdata

    Bytes::from(wire)
}

fn validator() -> ResponseValidator {
    ResponseValidator::new(
        0x1234,
        QNAME_LABELS.iter().map(|l| l.as_bytes().to_vec()).collect(),
        HRecordType::A,
        None,
        true,
    )
}

#[test]
fn uncompressed_answer_owner_name_is_canonicalized_in_raw_bytes() {
    let wire = uncompressed_response();
    assert!(
        wire.windows(3).any(|w| w == b"WwW"),
        "fixture must start out carrying randomized case"
    );

    let mut resp = ResponseParser::parse_bytes(wire).expect("fixture must parse");
    validator().canonicalize(&mut resp);

    let leaked: Vec<u8> = resp
        .raw_bytes
        .iter()
        .copied()
        .filter(u8::is_ascii_uppercase)
        .collect();
    assert!(
        leaked.is_empty(),
        "randomized case survived into cached wire: {:?}",
        String::from_utf8_lossy(&leaked)
    );

    // The parsed view and the wire must agree; a mismatch is how the two
    // representations silently diverge.
    assert_eq!(
        resp.message.queries[0].name().to_string(),
        "www.example.com."
    );
    assert_eq!(resp.message.answers[0].name.to_string(), "www.example.com.");
}

#[test]
fn canonicalization_preserves_length_and_parses_back() {
    let wire = uncompressed_response();
    let original_len = wire.len();

    let mut resp = ResponseParser::parse_bytes(wire).expect("fixture must parse");
    validator().canonicalize(&mut resp);

    assert_eq!(
        resp.raw_bytes.len(),
        original_len,
        "case changes preserve length, so no offset can have shifted"
    );
    let reparsed = ResponseParser::parse_bytes(resp.raw_bytes.clone())
        .expect("canonicalized wire must still be a valid DNS message");
    assert_eq!(reparsed.addresses, resp.addresses);
}

#[test]
fn truncated_or_malformed_wire_is_left_alone() {
    // A rewrite it cannot fully understand must be a no-op, never a partial edit.
    let full = uncompressed_response();
    for cut in [13, 20, 30, full.len() - 1] {
        let mut resp = ResponseParser::parse_bytes(full.clone()).unwrap();
        resp.raw_bytes = full.slice(0..cut);
        let before = resp.raw_bytes.clone();
        validator().canonicalize(&mut resp);
        assert_eq!(resp.raw_bytes, before, "truncation at {cut} was rewritten");
    }
}

#[test]
fn compressed_answer_owner_name_still_canonicalized() {
    // The case the question-only pass did handle — guard it against regression.
    let mut wire = Vec::new();
    wire.extend_from_slice(&0x1234u16.to_be_bytes());
    wire.extend_from_slice(&0x8180u16.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&QNAME_LABELS, &mut wire);
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to offset 12
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&60u32.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(&[203, 0, 113, 7]);

    let mut resp = ResponseParser::parse_bytes(Bytes::from(wire)).unwrap();
    validator().canonicalize(&mut resp);

    assert!(!resp.raw_bytes.iter().any(u8::is_ascii_uppercase));
    assert_eq!(resp.message.answers[0].name.to_string(), "www.example.com.");
}
