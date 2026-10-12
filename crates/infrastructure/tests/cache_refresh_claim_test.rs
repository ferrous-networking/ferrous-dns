//! What happens when a refresh timer fires: whether the cache hands the entry
//! to the worker, and what it arms next.
//!
//! These replace the tests of the per-minute candidate scan. Each old scan
//! case has a counterpart here: an entry inside the access window is claimed,
//! one outside it is left to expire until a hit brings it back, a permanent
//! entry never is, a claimed entry is not claimed twice, and hot entries rank
//! before cold ones.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::{coarse_clock, CacheKey};
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy, RefreshPriority,
    RefreshSenders, ScheduledRefresh,
};
use std::collections::BinaryHeap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn cache(refresh_threshold: f64, access_window_secs: u64) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    })
}

/// Wires a timer channel the test reads, standing in for the worker.
fn wire_timers(cache: &DnsCache, capacity: usize) -> mpsc::Receiver<ScheduledRefresh> {
    let (stale, _stale_rx) = mpsc::channel(16);
    let (schedule, schedule_rx) = mpsc::channel(capacity);
    cache.set_refresh_senders(RefreshSenders {
        stale,
        schedule: Some(schedule),
    });
    schedule_rx
}

fn address() -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec!["192.0.2.9".parse::<IpAddr>().unwrap()]),
    })
}

/// A CNAME never enters L1, so every lookup of it is an L2 hit.
fn cname() -> CachedData {
    CachedData::CanonicalName(Arc::from("target.example"))
}

fn timer(domain: &str, due_at_secs: u64) -> ScheduledRefresh {
    ScheduledRefresh {
        due_at_secs,
        key: CacheKey::new(domain, RecordType::A),
        retry: false,
    }
}

fn no_ranking() -> RefreshPriority {
    RefreshPriority {
        min_hit_rate: 0.0,
        min_frequency: 0,
    }
}

fn drain(rx: &mut mpsc::Receiver<ScheduledRefresh>) -> Vec<ScheduledRefresh> {
    let mut timers = Vec::new();
    while let Ok(timer) = rx.try_recv() {
        timers.push(timer);
    }
    timers
}

#[test]
fn test_insert_arms_a_timer_for_the_second_the_entry_falls_due() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    let mut timers = wire_timers(&cache, 16);
    let now = coarse_clock::coarse_now_secs();

    cache.insert("armed.example", RecordType::A, address(), 3600, None);

    let armed = drain(&mut timers);
    assert_eq!(armed.len(), 1, "one timer per stored entry: {armed:?}");
    assert_eq!(armed[0].key.domain, "armed.example");
    assert!(
        (now + 2700..=now + 2701).contains(&armed[0].due_at_secs),
        "a 3600 s entry falls due at 75% of its TTL, got {} from {now}",
        armed[0].due_at_secs
    );
}

#[test]
fn test_permanent_and_negative_entries_arm_nothing() {
    let cache = cache(0.0, u64::MAX);
    let mut timers = wire_timers(&cache, 16);

    cache.insert_permanent("local.example", RecordType::A, address(), 300);
    cache.insert(
        "missing.example",
        RecordType::A,
        CachedData::NegativeResponse,
        300,
        None,
    );

    assert!(drain(&mut timers).is_empty());
    let now = coarse_clock::coarse_now_secs();
    assert!(
        cache
            .claim_due_refresh(&timer("local.example", now + 1), now + 1, &no_ranking())
            .is_none(),
        "a local record is never renewed"
    );
}

#[test]
fn test_without_optimistic_refresh_nothing_is_armed() {
    let cache = cache(0.0, u64::MAX);
    let (stale, _stale_rx) = mpsc::channel(16);
    cache.set_refresh_senders(RefreshSenders {
        stale,
        schedule: None,
    });

    cache.insert("plain.example", RecordType::A, address(), 300, None);

    assert!(cache.get("plain.example", &RecordType::A).is_some());
    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        0,
        "no timer was ever attempted, so none was shed"
    );
}

#[test]
fn test_due_entry_inside_the_access_window_is_claimed_once() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    cache.insert("due.example", RecordType::A, address(), 300, None);
    let now = coarse_clock::coarse_now_secs();

    let first = cache.claim_due_refresh(&timer("due.example", now + 1), now + 1, &no_ranking());
    let second = cache.claim_due_refresh(&timer("due.example", now + 1), now + 1, &no_ranking());

    assert!(first.is_some(), "the due entry must be claimed");
    assert!(
        second.is_none(),
        "a claimed entry is being renewed and must not be claimed again"
    );
}

#[test]
fn test_timer_that_fires_before_the_entry_is_due_claims_nothing() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    cache.insert("early.example", RecordType::A, address(), 3600, None);
    let now = coarse_clock::coarse_now_secs();

    assert!(cache
        .claim_due_refresh(&timer("early.example", now + 10), now + 10, &no_ranking())
        .is_none());
    assert!(cache
        .claim_due_refresh(&timer("gone.example", now + 10), now + 10, &no_ranking())
        .is_none());
}

/// The timer of an entry that was renewed since, by a serve-stale repair or
/// a newer insert, is stale: that renewal armed the live one.
#[test]
fn test_timer_of_an_entry_renewed_since_claims_nothing() {
    coarse_clock::tick();
    let cache = cache(0.5, u64::MAX);
    let mut timers = wire_timers(&cache, 16);
    cache.insert("renewed.example", RecordType::A, address(), 300, None);
    let first = drain(&mut timers).remove(0);

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    assert!(cache.refresh_record(
        "renewed.example",
        &RecordType::A,
        Some(300),
        address(),
        None
    ));
    let renewed = drain(&mut timers);

    assert_eq!(renewed.len(), 1, "the renewal arms the next timer");
    assert!(renewed[0].due_at_secs > first.due_at_secs);
    assert!(
        cache
            .claim_due_refresh(&first, first.due_at_secs, &no_ranking())
            .is_none(),
        "the old timer must not renew the entry a second time"
    );
    assert!(cache
        .claim_due_refresh(&renewed[0], renewed[0].due_at_secs, &no_ranking())
        .is_some());
}

/// An entry nobody asked for within the access window is left to expire. Its
/// timer is spent, and the next hit arms a new one, due at once.
#[test]
fn test_entry_outside_the_access_window_rearms_on_its_next_hit() {
    coarse_clock::tick();
    let cache = cache(0.0, 0);
    let mut timers = wire_timers(&cache, 16);
    cache.insert("idle.example", RecordType::A, cname(), 300, None);
    let armed = drain(&mut timers).remove(0);

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    let now = coarse_clock::coarse_now_secs();
    assert!(
        cache
            .claim_due_refresh(&armed, now, &no_ranking())
            .is_none(),
        "an entry idle past the access window is not renewed"
    );
    assert!(
        drain(&mut timers).is_empty(),
        "and nothing re-arms it by itself"
    );

    assert!(cache.get("idle.example", &RecordType::A).is_some());
    let rearmed = drain(&mut timers);
    assert_eq!(rearmed.len(), 1, "a hit arms it again: {rearmed:?}");
    assert!(
        rearmed[0].due_at_secs <= now,
        "already due, so it fires at once"
    );
    assert!(
        cache
            .claim_due_refresh(&rearmed[0], now, &no_ranking())
            .is_some(),
        "back in use, it is renewed"
    );
}

/// A hit on an entry whose timer is pending arms nothing more.
#[test]
fn test_hits_on_an_armed_entry_arm_no_second_timer() {
    let cache = cache(0.75, u64::MAX);
    let mut timers = wire_timers(&cache, 16);
    cache.insert("busy.example", RecordType::A, cname(), 300, None);
    for _ in 0..10 {
        assert!(cache.get("busy.example", &RecordType::A).is_some());
    }

    assert_eq!(drain(&mut timers).len(), 1);
}

#[test]
fn test_full_timer_queue_is_shed_and_rearmed_by_a_later_hit() {
    let cache = cache(0.75, u64::MAX);
    let mut timers = wire_timers(&cache, 1);
    cache.insert("first.example", RecordType::A, cname(), 300, None);
    cache.insert("second.example", RecordType::A, cname(), 300, None);

    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        1,
        "the second timer found the queue full"
    );
    assert_eq!(drain(&mut timers).len(), 1);

    assert!(cache.get("second.example", &RecordType::A).is_some());
    let rearmed = drain(&mut timers);
    assert_eq!(
        rearmed.len(),
        1,
        "the shed entry is armed again on its next hit"
    );
    assert_eq!(rearmed[0].key.domain, "second.example");
}

/// An expired entry still inside its stale grace is worth renewing: clients
/// are being served it.
#[test]
fn test_stale_entry_still_in_grace_is_claimed() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    cache.insert("stale.example", RecordType::A, cname(), 1, None);

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    let now = coarse_clock::coarse_now_secs();

    assert!(cache
        .claim_due_refresh(&timer("stale.example", now), now, &no_ranking())
        .is_some());
}

#[test]
fn test_due_renewals_rank_hot_before_cold() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    cache.insert("cold.example", RecordType::A, cname(), 300, None);
    cache.insert("hot.example", RecordType::A, cname(), 300, None);
    for _ in 0..5 {
        assert!(cache.get("hot.example", &RecordType::A).is_some());
    }
    let priority = RefreshPriority {
        min_hit_rate: 0.0,
        min_frequency: 3,
    };
    let now = coarse_clock::coarse_now_secs() + 1;

    let mut due = BinaryHeap::new();
    for domain in ["cold.example", "hot.example"] {
        due.push(
            cache
                .claim_due_refresh(&timer(domain, now), now, &priority)
                .expect("both are due"),
        );
    }

    assert_eq!(due.pop().unwrap().key.domain, "hot.example");
    assert_eq!(due.pop().unwrap().key.domain, "cold.example");
}

/// `refresh_record` rebases the hit-rate window, so a name just renewed ranks
/// as cold until it is asked for again.
#[test]
fn test_renewal_rebases_the_hit_rate_used_for_ranking() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    cache.insert("renewed.example", RecordType::A, cname(), 300, None);
    cache.insert("untouched.example", RecordType::A, cname(), 300, None);
    for _ in 0..5 {
        assert!(cache.get("renewed.example", &RecordType::A).is_some());
        assert!(cache.get("untouched.example", &RecordType::A).is_some());
    }
    assert!(cache.refresh_record("renewed.example", &RecordType::A, Some(300), cname(), None));
    let priority = RefreshPriority {
        min_hit_rate: 2.0,
        min_frequency: 0,
    };
    let now = coarse_clock::coarse_now_secs() + 1;

    let mut due = BinaryHeap::new();
    for domain in ["renewed.example", "untouched.example"] {
        due.push(
            cache
                .claim_due_refresh(&timer(domain, now), now, &priority)
                .expect("both are due"),
        );
    }

    assert_eq!(due.pop().unwrap().key.domain, "untouched.example");
    assert_eq!(due.pop().unwrap().key.domain, "renewed.example");
}

#[test]
fn test_compaction_rearms_an_entry_whose_renewal_failed() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let mut timers = wire_timers(&cache, 16);
    cache.insert("failing.example", RecordType::A, cname(), 300, None);
    let armed = drain(&mut timers).remove(0);

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    let now = coarse_clock::coarse_now_secs();
    assert!(cache
        .claim_due_refresh(&armed, now, &no_ranking())
        .is_some());
    // The renewal failed: the worker releases the claim and arms nothing.
    cache.reset_refreshing("failing.example", &RecordType::A);

    assert!(cache.get("failing.example", &RecordType::A).is_some());
    assert!(
        drain(&mut timers).is_empty(),
        "a hit must not turn a failing upstream into one retry per hit"
    );

    cache.compact();
    let rearmed = drain(&mut timers);
    assert_eq!(
        rearmed.len(),
        1,
        "compaction gives it another try: {rearmed:?}"
    );
    assert_eq!(rearmed[0].key.domain, "failing.example");
}

#[test]
fn test_compaction_leaves_entries_on_schedule_alone() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    let mut timers = wire_timers(&cache, 16);
    cache.insert("on-time.example", RecordType::A, cname(), 3600, None);
    drain(&mut timers);

    cache.compact();

    assert!(drain(&mut timers).is_empty());
}
