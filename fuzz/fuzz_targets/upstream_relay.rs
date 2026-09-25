//! `wire_response::relay_with_edns` re-sections a cached upstream answer to
//! swap its OPT for ours, drop any TSIG or SIG(0) and, for a client without
//! DO, drop the DNSSEC RRs it did not ask for (`server.rs`). `cache_form`
//! stores an upstream answer for `relay_cached`, the fast path's relay. The
//! bytes come from the upstream, or from an off-path spoofer that won the
//! race.
//!
//! Beyond not panicking: relaying our own output again is a no-op, and when
//! hickory decodes the upstream message it decodes the relayed one to the same
//! RCODE and records (less the stripped ones) under our header and OPT, and
//! serving the cache form decodes to the same message as relaying directly.
//! Messages with a compression pointer into the header are skipped for those
//! checks: RFC 1035 forbids them, hickory follows them, and their target
//! moves under the ID rewrite every cached answer gets, relayed or not.
//!
//! The relay knobs come from the upstream ID, which the relay overwrites
//! anyway, so corpus entries stay plain DNS packets.
#![no_main]

use ferrous_dns_infrastructure::dns::fuzz_api;
use ferrous_dns_infrastructure::dns::wire_response::{self, EdnsReply};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{RData, Record, RecordType};
use libfuzzer_sys::fuzz_target;

const ID: u16 = 0xABCD;
/// The TTL the cache gives a record past its own (RFC 8767 §4).
const STALE_SERVE_TTL: u32 = 2;

/// The records a client with DO as given gets from `records`, answering a
/// `qtype` query (RFC 4035 §3.2.1, RFC 3225 §3). A TSIG or SIG(0) signs the
/// upstream's transaction with us and is never relayed (RFC 8945 §5.3, RFC
/// 2931 §3); hickory leaves one here as a SIG, or as an UPDATE's empty TSIG.
fn kept(records: &[Record], dnssec_ok: bool, qtype: Option<RecordType>) -> Vec<Record> {
    records
        .iter()
        .filter(|r| {
            let rtype = r.record_type();
            let signature = rtype == RecordType::TSIG
                || matches!(&r.data, RData::DNSSEC(DNSSECRData::SIG(sig))
                    if sig.input().type_covered == RecordType::ZERO);
            !signature
                && (dnssec_ok
                    || !matches!(
                        rtype,
                        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                    )
                    || qtype.is_some_and(|q| q == rtype || q == RecordType::ANY))
        })
        .cloned()
        .collect()
}

/// Blanks the RDATA hickory leaves as raw bytes (RP, AFSDB, MINFO, ...) for a
/// type whose names the relay decompresses: a pointer it re-aimed or inlined
/// names the same labels in other bytes.
fn blank_opaque_names(msg: &mut Message) {
    for record in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        if let RData::Unknown { code, rdata } = &mut record.data {
            if fuzz_api::rdata_has_names(u16::from(*code)) {
                *rdata = NULL::new();
            }
        }
    }
}

fuzz_target!(|upstream: &[u8]| {
    let Some(&[hi, lo]) = upstream.get(..2) else {
        return;
    };
    let knobs = u16::from_be_bytes([hi, lo]);
    let (rd, ad) = (knobs & 1 != 0, knobs & 2 != 0);
    let reply = EdnsReply {
        dnssec_ok: knobs & 4 != 0,
        cookie: (knobs & 8 != 0).then_some(&[0x55; 16]),
        ede: None,
    };
    let edns = (knobs & 16 == 0).then_some(&reply);
    let dnssec_ok = edns.is_some_and(|e| e.dnssec_ok);

    let Some(relayed) = wire_response::relay_with_edns(upstream, ID, rd, ad, edns) else {
        return;
    };
    let again = wire_response::relay_with_edns(&relayed, ID, rd, ad, edns);
    assert_eq!(
        again.as_deref(),
        Some(&relayed[..]),
        "relay is not idempotent"
    );

    let points_into_header = upstream
        .windows(2)
        .any(|w| w[0] >= 0xC0 && (u16::from(w[0] & 0x3F) << 8 | u16::from(w[1])) < 12);
    let Ok(mut source) = Message::from_vec(upstream) else {
        return;
    };
    if points_into_header {
        return;
    }
    blank_opaque_names(&mut source);
    let qtype = source.queries.first().map(|q| q.query_type());
    let mut got = Message::from_vec(&relayed).expect("relay made a valid message invalid");
    blank_opaque_names(&mut got);
    assert_eq!((got.metadata.id, got.metadata.recursion_desired), (ID, rd));
    assert_eq!(got.metadata.authentic_data, ad);
    assert_eq!(got.metadata.response_code, source.metadata.response_code);
    assert_eq!(got.queries, source.queries);
    assert_eq!(got.answers, kept(&source.answers, dnssec_ok, qtype));
    assert_eq!(got.authorities, kept(&source.authorities, dnssec_ok, qtype));
    assert_eq!(got.additionals, kept(&source.additionals, dnssec_ok, qtype));
    assert_eq!(
        got.edns.as_ref().map(|e| e.flags().dnssec_ok),
        edns.map(|e| e.dnssec_ok)
    );

    // The fast path serves clients without DO, from the cache form. An entry
    // as long-lived as a TTL can be, served before any time passed, keeps each
    // TTL but those below the stale TTL (RFC 8767 §4), which rise to it.
    if dnssec_ok || ad {
        return;
    }
    // The cache form keeps the DNSSEC RRs a DO client may ask for later, so it
    // walks exactly what relaying to a DO client walks; stripping them for this
    // client may have skipped a malformed one. On top of that it declines a
    // message whose names read TTL bytes, which aging would rewrite.
    let with_do = EdnsReply {
        dnssec_ok: true,
        cookie: None,
        ede: None,
    };
    let cached = wire_response::cache_form(upstream, u32::MAX, 0..=u32::MAX);
    let relays_with_do = wire_response::relay_with_edns(upstream, ID, rd, ad, Some(&with_do));
    let cached = match (cached, relays_with_do) {
        (Some(cached), Some(_)) => cached,
        (Some(_), None) => panic!("cached what a DO client cannot be relayed"),
        (None, Some(_)) => {
            assert!(
                fuzz_api::cache_form_declines_names(upstream),
                "relayable to a DO client but not cacheable"
            );
            return;
        }
        (None, None) => return,
    };
    let served = wire_response::relay_cached(&cached, ID, rd, edns, u32::MAX)
        .expect("relayed but not served from the cache");
    let mut served = Message::from_vec(&served).expect("the cache form served an invalid message");
    blank_opaque_names(&mut served);
    let mut expected = got;
    for record in expected
        .answers
        .iter_mut()
        .chain(&mut expected.authorities)
        .chain(&mut expected.additionals)
    {
        record.ttl = record.ttl.max(STALE_SERVE_TTL);
    }
    assert_eq!(served, expected, "the cache form serves another message");
});
