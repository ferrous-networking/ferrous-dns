//! Tests for Phase 2 of the cache optimization plan: negative cache TTL floor.
//!
//! The negative cache must enforce a `[300s, 3600s]` window on its TTLs so that
//! upstream responses with TTL=0 for NXDOMAIN (plus `cache_min_ttl=0` on the
//! general cache config) do not cause every repeated miss to escape to upstream.
//! Positive records are NOT affected — they keep following the configured
//! `min_ttl`/`max_ttl` bounds so short-lived records still drive the refresh
//! and access-window lifecycle as designed.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;

fn make_cache() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.0,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
        min_ttl: 0,
        max_ttl: 86_400,
    })
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().expect("valid IP");
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

#[test]
fn should_apply_300s_floor_on_negative_cache() {
    let cache = make_cache();
    coarse_clock::tick();

    cache.insert(
        "nothere.com",
        RecordType::A,
        CachedData::NegativeResponse,
        0,
        None,
    );

    let result = cache.get(&Arc::from("nothere.com"), &RecordType::A);
    let (data, dnssec, remaining) = result.expect("negative entry must be retrievable");

    assert!(matches!(data, CachedData::NegativeResponse));
    assert!(dnssec.is_none());
    let remaining_ttl = remaining.expect("negative entry carries a remaining TTL");
    assert!(
        remaining_ttl >= 300,
        "negative cache must floor TTL at 300s even when upstream returned TTL=0 (got {remaining_ttl})"
    );
}

#[test]
fn should_cap_at_3600s_for_huge_negative_ttl() {
    let cache = make_cache();
    coarse_clock::tick();

    cache.insert(
        "longlived.com",
        RecordType::A,
        CachedData::NegativeResponse,
        100_000,
        None,
    );

    let result = cache.get(&Arc::from("longlived.com"), &RecordType::A);
    let (_data, _dnssec, remaining) = result.expect("negative entry must be retrievable");
    let remaining_ttl = remaining.expect("negative entry carries a remaining TTL");
    assert!(
        remaining_ttl <= 3600,
        "negative cache must cap TTL at 3600s even for huge upstream TTLs (got {remaining_ttl})"
    );
}

#[test]
fn should_preserve_positive_record_ttl_exactly() {
    let cache = make_cache();
    coarse_clock::tick();

    cache.insert(
        "positive.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        5,
        None,
    );

    let result = cache.get(&Arc::from("positive.com"), &RecordType::A);
    let (_data, _dnssec, remaining) = result.expect("positive entry must be retrievable");
    let remaining_ttl = remaining.expect("positive entry carries a remaining TTL");
    assert!(
        (4..=5).contains(&remaining_ttl),
        "positive records must not receive the negative-cache floor; expected ~5s, got {remaining_ttl}"
    );
}

#[test]
fn should_preserve_positive_refresh_window_behavior() {
    // Proof that the negative-cache 300s floor does NOT leak into positive
    // records: a positive entry inserted with a 1s TTL stays bound to its own
    // lifecycle. After the TTL elapses (plus the stale-serve grace window the
    // project applies to positives), the entry is lazy-deleted on the next
    // `get`, i.e. it is neither served nor artificially preserved at 300s.
    //
    // Timing: STALE_GRACE_PERIOD_MULTIPLIER=2 (see `cache/record.rs`), so with
    // TTL=1 the stale window closes at 2s. Sleep 4s keeps the test under
    // 5s while leaving >=1s of slack for coarse-clock rounding and CI noise.
    let cache = make_cache();
    coarse_clock::tick();

    cache.insert(
        "shortlived.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        1,
        None,
    );

    // Sanity: positive record is live right after insert.
    assert!(
        cache
            .get(&Arc::from("shortlived.com"), &RecordType::A)
            .is_some(),
        "positive entry must be live immediately after insert"
    );

    // Advance past TTL + stale-serve window (ttl * 2 = 2s grace).
    // TTL=1 + grace=2 + 1s slack → sleep 4s.
    std::thread::sleep(std::time::Duration::from_secs(4));
    coarse_clock::tick();

    // Positive entry with TTL=1 and `min_ttl=0` must not be artificially
    // preserved by the negative floor (300s). Past the stale-serve window the
    // entry is lazy-deleted and `get` returns `None`.
    let after_expiry = cache.get(&Arc::from("shortlived.com"), &RecordType::A);
    assert!(
        after_expiry.is_none(),
        "positive record must expire at its own TTL; negative floor must not leak into positives"
    );
}
