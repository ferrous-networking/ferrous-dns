//! T0 spike: does hickory preserve mixed-case QNAME label bytes through an
//! emit -> parse wire round-trip? This is the precondition for implementing
//! 0x20 QNAME randomization via `hickory_proto::rr::Name`. If these assertions
//! hold, `build_query_hardened` can randomize case on the `Name`; if they ever
//! regress, fall back to stamping case directly on the serialized QNAME bytes.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::str::FromStr;

fn labels(name: &Name) -> Vec<Vec<u8>> {
    name.iter().map(|label| label.to_vec()).collect()
}

#[test]
fn name_from_str_lowercases_labels() {
    // FINDING: hickory `Name::from_str` lowercases labels, so 0x20 randomization
    // cannot go through `from_str` — it must build the Name from raw label bytes
    // (see `name_from_labels_preserves_case_through_roundtrip`).
    let name = Name::from_str("ExAmPlE.cOm").unwrap();
    let has_upper = name
        .iter()
        .any(|label| label.iter().any(u8::is_ascii_uppercase));
    assert!(!has_upper, "Name::from_str unexpectedly preserved case");
}

#[test]
fn name_from_labels_preserves_case_through_roundtrip() {
    // The viable 0x20 path: construct the Name from raw mixed-case label bytes,
    // which must survive both construction and the emit -> parse wire round-trip.
    let raw: [&[u8]; 2] = [b"eXaMpLe", b"NeT"];
    let original = Name::from_labels(raw.iter().map(|l| l.to_vec())).unwrap();

    let has_upper = original
        .iter()
        .any(|label| label.iter().any(u8::is_ascii_uppercase));
    assert!(
        has_upper,
        "Name::from_labels must keep label case; got {:?}",
        labels(&original)
    );

    let mut query = Query::new();
    query.set_name(original.clone());
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);

    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.add_query(query);

    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        message.emit(&mut encoder).unwrap();
    }

    let parsed = Message::from_vec(&buf).unwrap();
    let parsed_labels = labels(parsed.queries()[0].name());

    assert_eq!(
        labels(&original),
        parsed_labels,
        "from_labels mixed case must survive emit -> parse for 0x20 to work"
    );
}

#[test]
fn name_equality_is_case_insensitive() {
    // Documents the gotcha that drives the byte-wise 0x20 echo check: hickory's
    // `Name` PartialEq ignores case, so `==` cannot detect a 0x20 mismatch.
    let lower = Name::from_str("example.com").unwrap();
    let upper = Name::from_str("EXAMPLE.COM").unwrap();
    assert_eq!(
        lower, upper,
        "hickory Name equality should be case-insensitive"
    );
}

#[test]
fn mixed_case_qname_survives_wire_roundtrip() {
    let original = Name::from_str("eXaMpLe.NeT").unwrap();
    let original_labels = labels(&original);

    let mut query = Query::new();
    query.set_name(original.clone());
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);

    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.add_query(query);

    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        message.emit(&mut encoder).unwrap();
    }

    let parsed = Message::from_vec(&buf).unwrap();
    let parsed_labels = labels(parsed.queries()[0].name());

    assert_eq!(
        original_labels, parsed_labels,
        "hickory must preserve mixed-case label bytes through emit -> parse for 0x20 to work"
    );
}
