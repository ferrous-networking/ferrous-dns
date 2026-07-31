//! The 0x20 decoder: a hand-rolled label walker that rewrites owner names in
//! place on every upstream response
//! (`dns::forwarding::response_validator::lowercase_owner_names`).
//!
//! Reachable by the upstream resolver and by any off-path attacker who wins
//! the race against it, so the bytes are attacker-influenced.
#![no_main]

use bytes::Bytes;
use ferrous_dns_infrastructure::dns::fuzz_api;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let wire = Bytes::copy_from_slice(data);

    if let Some(lowered) = fuzz_api::lowercase_owner_names(&wire) {
        // Case folding preserves length: nothing in the header, no RDLENGTH and
        // no compression offset may shift.
        assert_eq!(
            lowered.len(),
            wire.len(),
            "0x20 decoder changed the message length"
        );
        // `Some` is only returned when a literal owner label carried uppercase,
        // so a no-op rewrite means the walk and the uppercase scan disagree
        // about which bytes are owner names.
        assert_ne!(
            lowered, wire,
            "0x20 decoder returned Some without rewriting anything"
        );
        // Only case may differ: same bytes under ASCII lowercasing.
        assert!(
            lowered
                .iter()
                .zip(wire.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase()),
            "0x20 decoder rewrote a byte that was not a case change"
        );
    }
});
