//! Client query fast path: the first code that touches bytes off the UDP
//! socket (`crates/cli/src/server/dns/udp.rs`), reachable by anyone who can
//! send a packet.
//!
//! Two properties are checked:
//!
//! 1. **No panic / no out-of-bounds.** `build_cache_hit_response` writes into a
//!    fixed 523-byte stack buffer and has already had an overflow bug (see the
//!    comment on `RESPONSE_BUF_LEN` in `wire_response.rs`).
//! 2. **The fast path and the slow path agree on the name.** A cache hit is
//!    keyed on `FastPathQuery::domain()`, while the slow path keys on
//!    hickory's `Name::to_utf8()` (`server.rs::handle_raw_udp_fallback`). If
//!    the two disagree, two different wire names share one cache entry.
//!
//! The answer-set size is derived from the query ID so that a corpus entry is
//! a plain DNS packet: the fuzzer still steers it, but seeds stay readable and
//! reusable by the other targets.
#![no_main]

use ferrous_dns_infrastructure::dns::fast_path;
use ferrous_dns_infrastructure::dns::forwarding::record_type_map::RecordTypeMapper;
use ferrous_dns_infrastructure::dns::wire_response;
use hickory_proto::op::Query;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Enough A records to cross the 523-byte buffer (16 bytes each).
const MAX_V4: u16 = 40;
/// Enough AAAA records to cross it too (28 bytes each).
const MAX_V6: u16 = 24;

/// The 12-byte DNS header, which the question section follows.
const HEADER_LEN: usize = 12;

fuzz_target!(|packet: &[u8]| {
    let Some(query) = fast_path::parse_query(packet) else {
        return;
    };

    // Only compare where both parsers accept. The reverse direction ("fast
    // path accepts => hickory accepts") is deliberately not asserted: the AR
    // walk in `parse_query` tolerates a truncated additional section on
    // purpose, which hickory rejects.
    //
    // Only the question is decoded, not the whole message. It is the part both
    // paths key the cache on, and it keeps the oracle off hickory's rdata
    // readers — one of which panics on input we cannot fix from here. A TSIG
    // record whose RDLENGTH is shorter than the fixed preamble makes
    // `rdata/tsig.rs:387` (hickory-proto 0.26.1) evaluate
    // `end_idx - decoder.index()` while building its *error* value, which
    // underflows. That upstream defect cannot panic the shipped server, where
    // `[profile.release]` sets `overflow-checks = false` and the wrapped value
    // only lands in a `DecodeError` field that is returned, never indexed
    // with; under a fuzz build it aborts the run before any assertion is
    // reached. `catch_unwind` is not an option: libfuzzer-sys installs a panic
    // hook that aborts the process before unwinding.
    let mut decoder = BinDecoder::new(packet);
    if decoder.read_slice(HEADER_LEN).is_ok() {
        if let Ok(question) = Query::read(&mut decoder) {
            let slow_path_domain = question.name().to_utf8();
            let slow_path_domain = slow_path_domain
                .trim_end_matches('.')
                .to_ascii_lowercase();

            assert_eq!(
                query.domain(),
                slow_path_domain,
                "fast path and slow path derive different cache keys from the same packet"
            );
            assert_eq!(
                RecordTypeMapper::from_hickory(question.query_type()),
                Some(query.record_type),
                "fast path and slow path disagree on the query type"
            );
        }
    }

    let mut addresses: Vec<IpAddr> = Vec::new();
    for i in 0..(query.id >> 8) % (MAX_V4 + 1) {
        addresses.push(IpAddr::V4(Ipv4Addr::from(0xC000_0200 + i as u32)));
    }
    for i in 0..(query.id & 0xFF) % (MAX_V6 + 1) {
        addresses.push(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)));
    }

    if let Some((buf, len)) = wire_response::build_cache_hit_response(&query, packet, &addresses, 300)
    {
        assert!(len <= buf.len(), "response length escaped the fixed buffer");
        assert!(
            wire_response::wire_fits_udp_buffer(len, query.client_max_size),
            "response exceeds the buffer the client advertised"
        );
    }
});
