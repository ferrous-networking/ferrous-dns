//! Deterministic regressions for findings that came out of the `fuzz/` suite.
//!
//! Every crash the fuzzer produces should land here as a named test with the
//! minimized input, so the bug stays fixed even if the corpus is lost.

use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::wire_response;
use hickory_proto::op::{Message, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
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

/// Decodes the question the way the `query_fast_path` target does — question
/// only, straight off the 12-byte header — and returns the cache key the slow
/// path would derive from it.
///
/// The target stops at the question so the oracle never reaches hickory's
/// rdata readers, where a TSIG record with a short RDLENGTH panics
/// (`rdata/tsig.rs:387`, hickory-proto 0.26.1). Keeping the same decode here
/// means the API the target depends on is compiled on stable too.
fn hickory_question_key(packet: &[u8]) -> Option<String> {
    let mut decoder = BinDecoder::new(packet);
    decoder.read_slice(12).ok()?;
    let question = Query::read(&mut decoder).ok()?;
    Some(
        question
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
    )
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

/// Found by the `query_fast_path` oracle after the first round of fixes: `#`
/// is printable ASCII, but hickory escapes it, so the same packet was keyed
/// `www.example.co#` by the fast path and `www.example.co\#` by the slow one.
/// "Printable" is the wrong test — the rule is whatever `Label::is_safe_ascii`
/// leaves alone.
#[test]
fn fast_path_rejects_printable_bytes_that_hickory_escapes() {
    for label in [
        b"co#".as_slice(),
        b"a+b".as_slice(),
        b"a/b".as_slice(),
        b"a:b".as_slice(),
        b"-leading-dash".as_slice(),
        b"mid*star".as_slice(),
    ] {
        let packet = query_packet(0x1234, &[b"www", label], 1, None);
        assert!(
            fast_path::parse_query(&packet).is_none(),
            "label {label:?} is escaped by hickory and must defer to the slow path"
        );
    }

    // The shapes hickory leaves alone must still take the fast path, or the
    // guard would have quietly disabled it for ordinary traffic.
    for labels in [
        vec![
            b"_dmarc".as_slice(),
            b"my-host9".as_slice(),
            b"com".as_slice(),
        ],
        vec![b"*".as_slice(), b"example".as_slice(), b"com".as_slice()],
    ] {
        let packet = query_packet(0x1234, &labels, 1, None);
        assert!(
            fast_path::parse_query(&packet).is_some(),
            "unescaped name must keep the fast path: {labels:?}"
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

/// The same invariant, swept exhaustively over every byte value in every
/// position of a label, which is what the fuzzer had to search for. Cheap
/// enough to run on stable, and it fails locally instead of 8 minutes into a
/// CI fuzz job.
#[test]
fn fast_path_key_matches_hickory_for_every_label_byte() {
    for byte in 0u8..=255 {
        for label in [vec![byte], vec![b'a', byte], vec![byte, b'a']] {
            let packet = query_packet(0x1234, &[&label, b"example", b"com"], 1, None);
            let Some(query) = fast_path::parse_query(&packet) else {
                continue;
            };
            let expected = hickory_question_key(&packet).expect("hickory decodes the question");

            assert_eq!(
                query.domain(),
                expected,
                "byte {byte:#04x} in label {label:?} takes the fast path with a different key"
            );
        }
    }
}

/// `crash-0fb15f6a` from the `query_fast_path` target: a query for `8we.com`
/// carrying a TSIG record whose RDLENGTH (6) is shorter than the fixed TSIG
/// preamble. Decoding that rdata panics inside hickory-proto 0.26.1 —
/// `rdata/tsig.rs:387` evaluates `end_idx - decoder.index()` while building
/// the `DecodeError` that reports the bad length, and it underflows.
///
/// The panic is upstream and on the error path; the shipped server builds with
/// `overflow-checks = false`, so the value wraps into a field of an error that
/// is returned rather than indexed with. What this pins is our side: the fast
/// path keys the packet by its question and agrees with hickory's decode of
/// that question, whatever the additional section carries.
#[test]
fn fast_path_handles_query_with_malformed_tsig_record() {
    let packet: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x38, 0x77,
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfa, 0xff, 0xff,
        0xd6, 0xfe, 0xf7, 0x00, 0x00, 0x06, 0x00, 0x00, 0x29, 0x10, 0x00, 0x06, 0x00, 0x01, 0x10,
        0x00, 0x06, 0x00, 0x01, 0xcc, 0x8b, 0x01, 0x00,
    ];

    let query = fast_path::parse_query(packet).expect("the question itself is well formed");
    assert_eq!(query.domain(), "8we.com");
    assert_eq!(
        hickory_question_key(packet).as_deref(),
        Some("8we.com"),
        "both paths must still agree on the name"
    );
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
