//! How entries leave the cache: each by its own timer, the second it dies,
//! with no pass over the cache looking for them. A positive entry dies at the
//! end of its stale grace, two TTLs after it was stored or last renewed; a
//! negative one when its TTL runs out. A full cache is evicted on the worker's
//! next tick.

#[path = "support/refresh.rs"]
mod refresh;

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::cache::{coarse_clock, CacheKey};
use ferrous_dns_infrastructure::dns::{
    CachedData, ColdThresholds, DnsCache, DnsCacheConfig, ScheduledRefresh, TimerInbox, TimerKind,
};
use refresh::{
    cname, drain, no_ranking, refresh_cache, refresh_cache_config, start_worker, wait_until,
    wire_timers,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn cache(access_window_secs: u64) -> Arc<DnsCache> {
    refresh_cache(100, 0.0, access_window_secs)
}

/// A cache with optimistic refresh off: an entry's only timer is its expiry.
fn cache_without_renewal() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        renew_ahead: false,
        ..refresh_cache_config(100, 0.0, u64::MAX)
    })
}

fn compactions(cache: &DnsCache) -> u64 {
    cache.metrics().compactions.load(Ordering::Relaxed)
}

/// The one timer armed since the last drain, which must be for `domain`.
fn only_timer(inbox: &TimerInbox, domain: &str) -> ScheduledRefresh {
    let mut timers = drain(inbox);
    assert_eq!(timers.len(), 1, "one timer for {domain}: {timers:?}");
    let timer = timers.remove(0);
    assert_eq!(timer.key.domain, domain);
    timer
}

/// Lets the coarse clock move on by a second.
fn wait_a_second() {
    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
}

/// Fires `timer` as the worker would at `now_secs`.
fn fire(cache: &DnsCache, timer: &ScheduledRefresh, now_secs: u64) {
    assert!(
        cache
            .claim_due_refresh(timer, now_secs, &no_ranking())
            .is_none(),
        "an expiry timer never claims a renewal"
    );
}

#[test]
fn test_entry_is_removed_when_its_timer_fires_and_not_before() {
    coarse_clock::tick();
    let cache = cache_without_renewal();
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("dying.example", RecordType::A, cname(), 300, None);
    let expiry = only_timer(&timers, "dying.example");

    // Expired at +300, still served stale until +600.
    fire(&cache, &expiry, expiry.due_at_secs - 1);
    assert_eq!(cache.len(), 1, "an entry inside its stale grace stays");

    fire(&cache, &expiry, expiry.due_at_secs);
    assert!(cache.is_empty(), "a dead entry goes");
    assert_eq!(compactions(&cache), 1);
}

/// A renewal moves the second the entry dies, so the timer of its old life
/// finds it alive and leaves it.
#[test]
fn test_entry_renewed_since_outlives_the_timer_of_its_old_life() {
    coarse_clock::tick();
    let cache = cache_without_renewal();
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("renewed.example", RecordType::A, cname(), 300, None);
    let first = only_timer(&timers, "renewed.example");

    wait_a_second();
    assert!(cache.refresh_record("renewed.example", &RecordType::A, Some(300), cname(), None));
    let second = only_timer(&timers, "renewed.example");
    assert!(second.due_at_secs > first.due_at_secs);

    fire(&cache, &first, first.due_at_secs);
    assert_eq!(cache.len(), 1, "the old life's timer must not remove it");
    fire(&cache, &second, second.due_at_secs);
    assert!(cache.is_empty());
}

/// An entry parked for lack of use keeps the timer that removes it, unless
/// it is used again and renewed first.
#[test]
fn test_parked_entry_is_removed_when_it_dies() {
    coarse_clock::tick();
    let cache = cache(0);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("idle.example", RecordType::A, cname(), 300, None);
    let renewal = only_timer(&timers, "idle.example");

    wait_a_second();
    fire(&cache, &renewal, coarse_clock::coarse_now_secs());
    let expiry = only_timer(&timers, "idle.example");
    assert_eq!(expiry.kind, TimerKind::Due);
    assert_eq!(
        expiry.due_at_secs,
        renewal.due_at_secs - 1 + 600,
        "two TTLs after insertion"
    );

    fire(&cache, &expiry, expiry.due_at_secs);
    assert!(cache.is_empty());
}

/// An answer with TTL 0 is never renewed ahead of expiry, and dies the
/// second it is stored.
#[test]
fn test_ttl_zero_entry_is_removed_on_the_next_tick() {
    coarse_clock::tick();
    let cache = cache(u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("zero.example", RecordType::A, cname(), 0, None);
    let expiry = only_timer(&timers, "zero.example");

    fire(&cache, &expiry, expiry.due_at_secs);
    assert!(cache.is_empty());
}

#[test]
fn test_negative_entry_is_removed_when_its_timer_fires() {
    coarse_clock::tick();
    let cache = cache(u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert(
        "missing.example",
        RecordType::A,
        CachedData::NegativeResponse,
        300,
        None,
    );
    let expiry = only_timer(&timers, "missing.example");
    assert_eq!(expiry.kind, TimerKind::NegativeExpiry);
    let key = CacheKey::new("missing.example", RecordType::A);

    assert!(!cache.expire_negative(&key, expiry.due_at_secs - 1));
    assert!(matches!(
        cache.get("missing.example", &RecordType::A),
        Some((CachedData::NegativeResponse, ..))
    ));

    assert!(cache.expire_negative(&key, expiry.due_at_secs));
    assert!(cache.get("missing.example", &RecordType::A).is_none());
    assert_eq!(compactions(&cache), 1);
}

/// Never called: every entry below falls due long after the test ends.
struct UnusedResolver;

#[async_trait]
impl DnsResolver for UnusedResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::AllUpstreamsServfail)
    }
}

/// A cache past `cache_max_entries` is evicted on the worker's next tick, a
/// batch at a time, tick after tick, until it is back under its capacity.
#[tokio::test]
async fn test_worker_evicts_a_full_cache_tick_after_tick() {
    // 10 entries at most, 2 evicted per pass.
    let cache = refresh_cache(10, 0.75, u64::MAX);
    let _worker = start_worker(&cache, Arc::new(UnusedResolver), no_ranking());
    for i in 0..14 {
        cache.insert(
            &format!("full-{i}.example"),
            RecordType::A,
            cname(),
            3600,
            None,
        );
    }

    let evicted = Arc::clone(&cache);
    assert!(
        wait_until(Duration::from_secs(6), || evicted.len() < 10).await,
        "three passes on three ticks bring 14 entries under 10; left {}",
        cache.len()
    );
}

/// Never answers, so each renewal holds its permit for good.
struct HangingResolver;

#[async_trait]
impl DnsResolver for HangingResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        std::future::pending().await
    }
}

/// A claimed renewal holds no timer while it waits for a permit. When hot
/// renewals keep every permit, a cold claim that dies in the queue is removed
/// by the worker all the same, and counted as shed.
#[tokio::test]
async fn test_claim_that_dies_waiting_for_a_permit_is_removed() {
    // Every renewal is due a second after it is stored.
    let cache = refresh_cache(100, 0.0, u64::MAX);
    let cold_below_one_hit = ColdThresholds {
        min_hit_rate: 0.0,
        min_frequency: 1,
    };
    let _worker = start_worker(&cache, Arc::new(HangingResolver), cold_below_one_hit);
    // Sixteen hot renewals take every permit and never give one back.
    for i in 0..16 {
        let name = format!("hot-{i}.example");
        cache.insert(&name, RecordType::A, cname(), 300, None);
        assert!(cache.get(&name, &RecordType::A).is_some());
    }
    // Cold, so it queues behind them; TTL 1, so it dies 2 s after insertion.
    cache.insert("cold.example", RecordType::A, cname(), 1, None);

    let waited = Arc::clone(&cache);
    assert!(
        wait_until(Duration::from_secs(5), || waited.len() == 16).await,
        "the dead claim must leave the cache; {} entries",
        cache.len()
    );
    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        1
    );
}
