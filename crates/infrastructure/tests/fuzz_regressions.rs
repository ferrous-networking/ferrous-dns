//! Deterministic regressions for findings that came out of the `fuzz/` suite.
//!
//! Every crash the fuzzer produces should land here as a named test with the
//! minimized input, so the bug stays fixed even if the corpus is lost.

use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::wire_response;
use hickory_proto::op::Message;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Builds a DNS query packet. `labels` are written verbatim, so a label may
/// carry bytes a well-behaved resolver would never send.
fn query_packet(id: u16, labels: &[&[u8]], qtype: u16, edns_payload: Option<u16>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&u16::from(edns_payload.is_some()).to_be_bytes()); // ARCOUNT

    for label in labels {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    if let Some(payload) = edns_payload {
        buf.push(0); // root owner name
        buf.extend_from_slice(&41u16.to_be_bytes()); // OPT
        buf.extend_from_slice(&payload.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]); // extended rcode, version, flags
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    }

    buf
}

/// The cache key is the label sequence flattened with `.`, so a single label
/// containing literal dots used to produce the same key as the multi-label
/// name that reads identically — two distinct wire names, one cache entry.
#[test]
fn fast_path_rejects_label_with_embedded_dot() {
    let packet = query_packet(0x1234, &[b"ads.example.com"], 1, None);
    assert!(fast_path::parse_query(&packet).is_none());

    // The equivalent well-formed name is still served by the fast path.
    let packet = query_packet(0x1234, &[b"ads", b"example", b"com"], 1, None);
    let query = fast_path::parse_query(&packet).expect("well-formed name takes the fast path");
    assert_eq!(query.domain(), "ads.example.com");
}

/// `FastPathQuery::domain()` decodes with `from_utf8(..).unwrap_or_default()`,
/// so a non-UTF-8 label used to collapse to the empty string — making every
/// such name share one cache key.
#[test]
fn fast_path_rejects_non_utf8_label() {
    let packet = query_packet(0x1234, &[&[0xFF, 0xFE, 0xFD], b"com"], 1, None);
    assert!(fast_path::parse_query(&packet).is_none());
}

/// Found by the `query_fast_path` oracle: hickory's `Name::to_utf8()` decodes
/// an A-label back to Unicode, so the slow path keys `xn--bcher-kva.de` as
/// `bücher.de`. The fast path kept the A-label, giving one query two cache
/// keys; it now defers IDN names to the slow path.
#[test]
fn fast_path_rejects_idn_a_labels() {
    for labels in [
        vec![b"xn--bcher-kva".as_slice(), b"de".as_slice()],
        vec![b"XN--BCHER-KVA".as_slice(), b"de".as_slice()],
        vec![b"www".as_slice(), b"xn--80ak6aa92e".as_slice()],
    ] {
        let packet = query_packet(0x1234, &labels, 1, None);
        assert!(
            fast_path::parse_query(&packet).is_none(),
            "IDN label must defer to the slow path: {labels:?}"
        );
    }
}

#[test]
fn fast_path_rejects_backslash_and_control_bytes() {
    for label in [
        b"ex\\ample".as_slice(),
        b"ex\x00ample".as_slice(),
        b"ex ample".as_slice(),
    ] {
        let packet = query_packet(0x1234, &[label, b"com"], 1, None);
        assert!(
            fast_path::parse_query(&packet).is_none(),
            "label {label:?} must not reach the cache key verbatim"
        );
    }
}

/// The invariant the `query_fast_path` fuzz target asserts: whenever both
/// parsers accept a packet, they must derive the same cache key. The slow path
/// key is built in `server.rs::handle_raw_udp_fallback`.
#[test]
fn fast_path_and_hickory_derive_the_same_key() {
    for labels in [
        vec![b"www".as_slice(), b"example".as_slice(), b"com".as_slice()],
        vec![b"WwW".as_slice(), b"ExAmPlE".as_slice(), b"CoM".as_slice()],
        vec![
            b"_dmarc".as_slice(),
            b"example".as_slice(),
            b"org".as_slice(),
        ],
        vec![],
    ] {
        let packet = query_packet(0x1234, &labels, 1, None);
        let Some(query) = fast_path::parse_query(&packet) else {
            continue;
        };
        let message = Message::from_vec(&packet).expect("hickory parses the same packet");
        let expected = message.queries[0].name().to_utf8();
        let expected = expected.trim_end_matches('.').to_ascii_lowercase();

        assert_eq!(query.domain(), expected, "labels: {labels:?}");
    }
}

/// `build_cache_hit_response` writes into a fixed 523-byte stack buffer. A
/// large RRset combined with a high EDNS buffer size used to overflow it and
/// panic the UDP worker; it must decline and let the slow path answer.
#[test]
fn cache_hit_response_declines_oversized_rrset() {
    let packet = query_packet(0x1234, &[b"example", b"com"], 1, Some(4096));
    let query = fast_path::parse_query(&packet).expect("valid A query");
    assert!(matches!(query.kind, FastPathKind::IpAddress));
    assert_eq!(query.client_max_size, 4096);

    let addresses: Vec<IpAddr> = (0..40)
        .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)))
        .collect();

    assert!(
        wire_response::build_cache_hit_response(&query, &packet, &addresses, u32::MAX).is_none()
    );
}

#[test]
fn cache_hit_response_stays_inside_the_fixed_buffer() {
    let packet = query_packet(0x1234, &[b"example", b"com"], 1, Some(4096));
    let query = fast_path::parse_query(&packet).expect("valid A query");
    let addresses = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];

    let (buf, len) = wire_response::build_cache_hit_response(&query, &packet, &addresses, 300)
        .expect("a single A record fits");

    assert!(len <= buf.len());
    assert!(wire_response::wire_fits_udp_buffer(
        len,
        query.client_max_size
    ));
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x1234);
}

/// Replays the versioned seed corpus of the `query_fast_path` target through
/// the same invariants the fuzz harness asserts. Keeps the oracle honest on
/// stable CI, where nightly and libFuzzer are not available.
#[test]
fn query_fast_path_seed_corpus_is_clean() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus/query_fast_path")
        .canonicalize()
        .expect("seed corpus is versioned alongside the fuzz targets");

    let mut seeds = 0;
    for entry in std::fs::read_dir(&corpus).expect("corpus is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_none_or(|ext| ext != "bin") {
            continue;
        }
        seeds += 1;

        let packet = std::fs::read(&path).expect("readable seed");
        let Some(query) = fast_path::parse_query(&packet) else {
            continue;
        };

        if let Ok(message) = Message::from_vec(&packet) {
            if let Some(question) = message.queries.first() {
                let expected = question.name().to_utf8();
                let expected = expected.trim_end_matches('.').to_ascii_lowercase();
                assert_eq!(query.domain(), expected, "seed: {}", path.display());
            }
        }

        let addresses = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];
        if let Some((buf, len)) =
            wire_response::build_cache_hit_response(&query, &packet, &addresses, 300)
        {
            assert!(len <= buf.len(), "seed: {}", path.display());
        }
    }

    assert!(seeds > 0, "no seeds found in {}", corpus.display());
}
