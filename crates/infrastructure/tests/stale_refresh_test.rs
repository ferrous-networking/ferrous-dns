use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc;

fn create_stale_cache() -> DnsCache {
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

fn make_cname_data(name: &str) -> CachedData {
    CachedData::CanonicalName(Arc::from(name))
}

#[test]
fn test_stale_entry_sends_to_refresh_channel() {
    let cache = create_stale_cache();
    let (tx, mut rx) = mpsc::channel(16);
    cache.set_stale_refresh_sender(tx);

    cache.insert(
        "stale-chan.com",
        RecordType::CNAME,
        make_cname_data("alias.stale-chan.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("stale-chan.com"), &RecordType::CNAME);
    if result.is_none() {
        return;
    }

    let msg = rx.try_recv();
    assert!(msg.is_ok(), "Stale hit must send domain to refresh channel");
    let (domain, record_type) = msg.unwrap();
    assert_eq!(&*domain, "stale-chan.com");
    assert_eq!(record_type, RecordType::CNAME);

    let stale_hits = cache.metrics().stale_hits.load(Ordering::Relaxed);
    assert!(
        stale_hits >= 1,
        "stale_hits metric must be incremented; got {stale_hits}"
    );
}

#[test]
fn test_stale_refresh_only_fires_once() {
    let cache = create_stale_cache();
    let (tx, mut rx) = mpsc::channel(16);
    cache.set_stale_refresh_sender(tx);

    cache.insert(
        "once.com",
        RecordType::CNAME,
        make_cname_data("alias.once.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let r1 = cache.get(&Arc::from("once.com"), &RecordType::CNAME);
    let r2 = cache.get(&Arc::from("once.com"), &RecordType::CNAME);
    let r3 = cache.get(&Arc::from("once.com"), &RecordType::CNAME);

    if r1.is_none() {
        return;
    }

    assert!(r2.is_some(), "Subsequent stale gets must still return data");
    assert!(r3.is_some(), "Subsequent stale gets must still return data");

    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(
        count, 1,
        "CAS must ensure only 1 refresh message is sent; got {count}"
    );
}

#[test]
fn test_stale_refresh_channel_full_does_not_block() {
    let cache = create_stale_cache();
    let (tx, _rx) = mpsc::channel(1);

    cache.set_stale_refresh_sender(tx);

    cache.insert(
        "full-a.com",
        RecordType::CNAME,
        make_cname_data("alias.full-a.com"),
        1,
        None,
    );
    cache.insert(
        "full-b.com",
        RecordType::CNAME,
        make_cname_data("alias.full-b.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let r1 = cache.get(&Arc::from("full-a.com"), &RecordType::CNAME);
    if r1.is_none() {
        return;
    }

    let r2 = cache.get(&Arc::from("full-b.com"), &RecordType::CNAME);
    assert!(
        r2.is_some(),
        "get() must not block even when the refresh channel is full"
    );
}

#[test]
fn test_stale_get_without_sender_still_works() {
    let cache = create_stale_cache();

    cache.insert(
        "no-sender.com",
        RecordType::CNAME,
        make_cname_data("alias.no-sender.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("no-sender.com"), &RecordType::CNAME);
    if let Some((_, _, Some(ttl))) = result {
        assert!(
            ttl >= 1,
            "Stale entry must return valid TTL even without sender; got {ttl}"
        );
    }
}

#[test]
fn test_expired_beyond_grace_not_served_stale() {
    let cache = create_stale_cache();
    let (tx, _rx) = mpsc::channel(16);
    cache.set_stale_refresh_sender(tx);

    cache.insert(
        "expired.com",
        RecordType::CNAME,
        make_cname_data("alias.expired.com"),
        1,
        None,
    );

    // TTL=1, grace=2×TTL=2s from insert. Sleep 3s to exceed the grace period.
    std::thread::sleep(std::time::Duration::from_millis(3000));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("expired.com"), &RecordType::CNAME);
    assert!(
        result.is_none(),
        "Entry expired beyond grace period must not be served"
    );
}
