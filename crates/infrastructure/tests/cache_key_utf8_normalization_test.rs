//! Regression tests for BUG-01: the oversized-domain normalization paths in
//! the cache key builders used to lowercase with `b.to_ascii_lowercase() as char`.
//!
//! `u8 as char` reinterprets the byte as a Unicode code point, so any byte
//! from 0x80 upwards (i.e. every continuation byte of a multi-byte UTF-8
//! sequence) got re-encoded as the two-byte UTF-8 form of U+0080..U+00FF.
//! The resulting key no longer matched the domain it was derived from, so an
//! entry stored under it could never be found again.
//!
//! These paths are cold — they only run past 253 bytes (`CacheKey`) or 260
//! bytes of `"Type:domain"` (L1) — but the local-records API and blocklist
//! import can feed arbitrary strings into them.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::data::CachedDnssecStatus;
use ferrous_dns_infrastructure::dns::cache::key::CacheKey;
use ferrous_dns_infrastructure::dns::cache::l1::{l1_clear, l1_get, l1_insert};
use std::net::IpAddr;
use std::sync::Arc;

/// A >253-byte domain mixing uppercase ASCII (to force the slow path) with
/// multi-byte UTF-8 (to expose the `as char` re-encoding).
fn long_non_ascii_domain() -> String {
    let d = format!("{}ção-ÜBER-café.EXAMPLE.com", "A".repeat(280));
    assert!(d.len() > 253, "fixture must exceed the CacheKey fast path");
    assert!(!d.is_ascii(), "fixture must contain multi-byte UTF-8");
    d
}

#[test]
fn should_preserve_utf8_bytes_when_normalizing_oversized_domain() {
    let domain = long_non_ascii_domain();
    let key = CacheKey::new(&domain, RecordType::A);

    assert_eq!(
        key.domain.as_str(),
        domain.to_ascii_lowercase(),
        "CacheKey must lowercase ASCII only and leave multi-byte UTF-8 untouched"
    );
    assert_eq!(
        key.domain.len(),
        domain.len(),
        "ASCII lowercasing must not change the byte length; got {} for a {}-byte input",
        key.domain.len(),
        domain.len()
    );
}

#[test]
fn should_match_case_variants_of_oversized_non_ascii_domain() {
    let upper = long_non_ascii_domain();
    let lower = upper.to_ascii_lowercase();

    // `upper` takes the oversized slow path, `lower` takes the already-lowercase
    // fast path. Before the fix these produced different keys, so an entry
    // inserted under the mixed-case name was a permanent, silent cache miss.
    assert_eq!(
        CacheKey::new(&upper, RecordType::A),
        CacheKey::new(&lower, RecordType::A),
        "case variants of the same oversized domain must map to the same cache key"
    );
}

#[test]
fn should_round_trip_oversized_non_ascii_domain_through_l1() {
    l1_clear();

    let domain = long_non_ascii_domain().to_ascii_lowercase();
    assert!(
        RecordType::A.as_str().len() + 1 + domain.len() > 260,
        "fixture must exceed the L1 stack-buffer fast path"
    );

    let addr: IpAddr = "203.0.113.7".parse().unwrap();
    let expires = ferrous_dns_infrastructure::dns::cache::coarse_clock::coarse_now_secs() + 300;
    l1_insert(
        &domain,
        &RecordType::A,
        Arc::new(vec![addr]),
        CachedDnssecStatus::Insecure,
        expires,
    );

    let hit = l1_get(&domain, &RecordType::A);
    assert!(
        hit.is_some(),
        "an oversized non-ASCII domain must be retrievable from L1 after insert"
    );
    assert_eq!(hit.unwrap().0.as_slice(), [addr]);

    l1_clear();
}

#[test]
fn should_not_use_u8_as_char_in_cache_key_builders() {
    for src in [
        include_str!("../src/dns/cache/key.rs"),
        include_str!("../src/dns/cache/l1.rs"),
    ] {
        assert!(
            !src.contains("as char"),
            "`u8 as char` corrupts non-ASCII bytes; lowercase over bytes instead"
        );
    }
}
