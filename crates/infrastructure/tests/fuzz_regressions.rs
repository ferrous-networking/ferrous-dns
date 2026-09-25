//! Deterministic regressions for findings that came out of the `fuzz/` suite.
//!
//! Every crash the fuzzer produces should land here as a named test with the
//! minimized input, so the bug stays fixed even if the corpus is lost.

use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::wire_response::{self, EdnsReply};
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

/// `build_cache_hit_response` writes into a fixed 523-byte buffer. A
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

    assert!(wire_response::build_cache_hit_response(
        &query,
        &packet,
        &addresses,
        u32::MAX,
        &mut [0u8; wire_response::RESPONSE_BUF_LEN]
    )
    .is_none());
}

#[test]
fn cache_hit_response_stays_inside_the_fixed_buffer() {
    let packet = query_packet(0x1234, &[b"example", b"com"], 1, Some(4096));
    let query = fast_path::parse_query(&packet).expect("valid A query");
    let addresses = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];

    let mut buf = [0u8; wire_response::RESPONSE_BUF_LEN];
    let len = wire_response::build_cache_hit_response(&query, &packet, &addresses, 300, &mut buf)
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
        let mut buf = [0u8; wire_response::RESPONSE_BUF_LEN];
        if let Some(len) =
            wire_response::build_cache_hit_response(&query, &packet, &addresses, 300, &mut buf)
        {
            assert!(len <= buf.len(), "seed: {}", path.display());
        }
    }

    assert!(seeds > 0, "no seeds found in {}", corpus.display());
}

/// BADCOOKIE is RCODE 23: header 7 plus 1 in the OPT's extended-RCODE byte.
/// Swapping in our OPT used to zero that byte, turning it into YXRRSET.
#[test]
fn relay_keeps_the_upstream_extended_rcode() {
    let upstream = b"\x00\x08\x81\x87\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\
                     \x00\x01\x00\x01\x00\x00\x29\x04\xd0\x01\x00\x00\x00\x00\x00";
    let ours = EdnsReply {
        dnssec_ok: false,
        cookie: Some(&[0x55; 16]),
        ede: None,
    };
    let relayed = wire_response::relay_with_edns(upstream, 1, true, false, Some(&ours)).unwrap();
    let rcode = Message::from_vec(&relayed).unwrap().metadata.response_code;
    assert_eq!(u16::from(rcode), 23);

    // Without an OPT of our own the extended bits have nowhere to go.
    assert!(wire_response::relay_with_edns(upstream, 1, true, false, None).is_none());
}

/// `crash-53ce8e0a` from the `upstream_relay` target: an NXDOMAIN whose only
/// additional record is a TSIG. The relay appended our OPT behind it, and
/// hickory rejects any record after a TSIG (`RecordAfterSig`, RFC 8945 §5.1).
/// The TSIG signs the upstream's transaction with us, so neither the client
/// nor the cache gets it (RFC 8945 §5.3).
#[test]
fn relay_drops_a_tsig_rather_than_append_an_opt_behind_it() {
    let upstream = b"\x00\x00\x81\x83\x00\x01\x00\x00\x00\x00\x00\x01\x04nope\x03com\x00\
                     \x00\x01\x00\x01\
                     \x00\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x11\
                     \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(Message::from_vec(upstream).unwrap().signature.is_some());
    let ours = EdnsReply {
        dnssec_ok: false,
        cookie: Some(&[0x55; 16]),
        ede: None,
    };
    let relayed = wire_response::relay_with_edns(upstream, 1, true, false, Some(&ours))
        .expect("re-sectioned");
    let cached = wire_response::cache_form(upstream, 60, 0..=u32::MAX).expect("cacheable");
    let served = wire_response::relay_cached(&cached, 1, true, Some(&ours), 60).expect("served");
    for reply in [relayed, served] {
        let msg = Message::from_vec(&reply).expect("relayed message decodes");
        assert_eq!(u16::from(msg.metadata.response_code), 3);
        assert!(msg.signature.is_none() && msg.additionals.is_empty());
        assert!(msg.edns.is_some());
    }
}

/// `crash-11436e02` from the `upstream_relay` target: a SIG with an empty
/// RDATA. Telling SIG(0) apart read its type-covered field past the record,
/// from whatever follows it: garbage upstream, our OPT once relayed, which
/// opens with the two zero bytes of SIG(0). So a second pass over our own
/// output, as serving a cache form takes, dropped the record the first kept.
#[test]
fn relay_reads_a_sig_type_covered_field_inside_its_rdata() {
    let upstream = b"\x00\x00\x81\x80\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\
                     \x00\x01\x00\x01\
                     \x00\x00\x18\x00\x01\x00\x00\x00\x00\x00\x00";
    let ours = EdnsReply {
        dnssec_ok: false,
        cookie: None,
        ede: None,
    };
    let once = wire_response::relay_with_edns(upstream, 1, true, false, Some(&ours)).unwrap();
    let twice = wire_response::relay_with_edns(&once, 1, true, false, Some(&ours));
    assert_eq!(twice.as_deref(), Some(&once[..]));
}

/// `crash-aa9f0262` from the `upstream_relay` target: a glue owner whose
/// pointer names labels at the tail of the answer's RDATA, and those run on
/// into the root owner of the OPT that follows. The pointer's target sits
/// before the dropped OPT, so it was kept as is, and the name picked up
/// whatever moved into the OPT's place — the glue record itself, a loop.
#[test]
fn relay_keeps_a_name_whose_labels_run_into_the_dropped_opt() {
    let upstream = b"\x11\x11\x81\x80\x00\x01\x00\x01\x00\x00\x00\x02\x07example\x03com\x00\
                     \x00\x10\x00\x01\
                     \xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x04\x03bar\
                     \x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00\
                     \x03foo\xc0\x29\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01";
    let source = Message::from_vec(upstream).unwrap();
    assert_eq!(source.additionals[0].name.to_ascii(), "foo.bar.");
    let ours = EdnsReply {
        dnssec_ok: false,
        cookie: None,
        ede: None,
    };
    let relayed = wire_response::relay_with_edns(upstream, 1, true, false, Some(&ours)).unwrap();
    let cached = wire_response::cache_form(upstream, 60, 0..=u32::MAX).unwrap();
    let served = wire_response::relay_cached(&cached, 1, true, Some(&ours), 60).unwrap();
    for reply in [relayed, served] {
        let msg = Message::from_vec(&reply).expect("relayed message decodes");
        assert_eq!(msg.additionals, source.additionals);
    }
}

/// `crash-a616f390` from the `upstream_relay` target: an RRSIG with an empty
/// RDATA behind the upstream OPT. Once the OPT is dropped, every later record
/// is copied field by field. A client without DO never sees the RRSIG, so its
/// relay drops it unread; the cache form keeps DNSSEC RRs for DO clients,
/// walks it and declines. The harness had assumed anything relayed is
/// cacheable. The contract is that the cache form and the DO relay accept the
/// same messages.
#[test]
fn a_malformed_rrsig_is_stripped_for_plain_clients_but_never_cached() {
    let upstream = b"\x00\x00\x81\x80\x00\x01\x00\x00\x00\x00\x00\x02\x07example\x03com\x00\
                     \x00\x01\x00\x01\
                     \x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00\
                     \xc0\x0c\x00\x2e\x00\x01\x00\x00\x00\x3c\x00\x00";
    let plain = EdnsReply {
        dnssec_ok: false,
        cookie: None,
        ede: None,
    };
    let with_do = EdnsReply {
        dnssec_ok: true,
        ..plain
    };
    let relayed = wire_response::relay_with_edns(upstream, 1, true, false, Some(&plain))
        .expect("a plain client gets the answer without the RRSIG");
    let msg = Message::from_vec(&relayed).unwrap();
    assert!(msg.additionals.is_empty() && msg.edns.is_some());
    assert!(wire_response::relay_with_edns(upstream, 1, true, false, Some(&with_do)).is_none());
    assert!(wire_response::cache_form(upstream, 60, 0..=u32::MAX).is_none());
}

/// `crash-4bdbba63` from the `upstream_relay` target: a glue owner whose
/// pointer lands on the CLASS/TTL bytes of the record before it, so its labels
/// are read out of that TTL. Counting the TTL down in the cache rewrote them,
/// and the cache served the glue under another name than the upstream sent.
/// A relay copies TTLs as they are; the cache now declines such a message.
#[test]
fn a_name_read_from_ttl_bytes_is_relayed_but_not_cached() {
    let upstream = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x02\x07example\x03czm\x01\x00\x00\
                     \x00\x0f\x00\x01\
                     \xc0\x0c\x00\x0f\x00\x01\x00\x00\x01\x2c\x00\x07\x00\x0a\x02ex\xc0\x0c\
                     \x00\x20\x29\x04\xd0\x00\x00\x00\x00\x00\x1c\x00\x0a\x00\x0a\x00\x00\x00\x7c\x7c\x00\
                     \x00\x00\x1c\x00\x0a\x0a\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02mx\
                     \xc0\x35\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc5\x00\x02\x26";
    let plain = EdnsReply {
        dnssec_ok: false,
        cookie: None,
        ede: None,
    };
    let relayed = wire_response::relay_with_edns(upstream, 1, true, false, Some(&plain))
        .expect("the relay copies the TTL the glue name is read from as is");
    let source = Message::from_vec(upstream).unwrap();
    let msg = Message::from_vec(&relayed).unwrap();
    assert_eq!(msg.additionals[1].name, source.additionals[1].name);
    assert!(wire_response::cache_form(upstream, 60, 0..=u32::MAX).is_none());
}

/// `crash-6a5a0cf7` from the `upstream_relay` target: an AFSDB whose name's
/// first label runs past its RDATA. Nothing is dropped ahead of it, so the
/// relay copies it as is; the cache form walks every name to find the TTLs
/// they might read, cannot bound this one and declines. The harness had
/// walked the DO relay instead, where our appended OPT ends the run cleanly.
#[test]
fn a_name_overrunning_its_rdata_is_relayed_but_not_cached() {
    let upstream = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\
                     \x00\x12\x00\x01\
                     \xc0\x0c\x00\x12\x00\x01\x00\x00\x01\x2c\x00\x05\x00\x0a\x05ab";
    let plain = EdnsReply {
        dnssec_ok: false,
        cookie: None,
        ede: None,
    };
    assert!(wire_response::relay_with_edns(upstream, 1, true, false, Some(&plain)).is_some());
    assert!(wire_response::cache_form(upstream, 60, 0..=u32::MAX).is_none());
}
