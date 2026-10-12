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
    RefreshSenders, ScheduledRefresh, TimerInbox,
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

/// Wires a timer inbox the test reads, standing in for the worker.
fn wire_timers(cache: &DnsCache, capacity: usize) -> Arc<TimerInbox> {
    let (stale, _stale_rx) = mpsc::channel(16);
    let inbox = Arc::new(TimerInbox::new(capacity));
    cache.set_refresh_senders(RefreshSenders {
        stale,
        schedule: Some(Arc::clone(&inbox)),
    });
    inbox
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

fn drain(inbox: &TimerInbox) -> Vec<ScheduledRefresh> {
    let mut timers = Vec::new();
    inbox.drain(|timer| timers.push(timer));
    timers
}

#[test]
fn test_insert_arms_a_timer_for_the_second_the_entry_falls_due() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    let timers = wire_timers(&cache, 16);
    let now = coarse_clock::coarse_now_secs();

    cache.insert("armed.example", RecordType::A, address(), 3600, None);

    let armed = drain(&timers);
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
    let timers = wire_timers(&cache, 16);

    cache.insert_permanent("local.example", RecordType::A, address(), 300);
    cache.insert(
        "missing.example",
        RecordType::A,
        CachedData::NegativeResponse,
        300,
        None,
    );

    assert!(drain(&timers).is_empty());
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
    let timers = wire_timers(&cache, 16);
    cache.insert("renewed.example", RecordType::A, address(), 300, None);
    let first = drain(&timers).remove(0);

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    assert!(cache.refresh_record(
        "renewed.example",
        &RecordType::A,
        Some(300),
        address(),
        None
    ));
    let renewed = drain(&timers);

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
    let timers = wire_timers(&cache, 16);
    cache.insert("idle.example", RecordType::A, cname(), 300, None);
    let armed = drain(&timers).remove(0);

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
        drain(&timers).is_empty(),
        "and nothing re-arms it by itself"
    );

    assert!(cache.get("idle.example", &RecordType::A).is_some());
    let rearmed = drain(&timers);
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

/// After a renewal nobody has asked for, a TTL under a minute is not renewed
/// again, since it would renew more than once a minute; a TTL of a minute or
/// more is, for as long as it stays inside the access window.
#[test]
fn test_unasked_renewal_continues_only_for_ttls_of_a_minute_or_more() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    cache.insert("short.example", RecordType::A, cname(), 30, None);
    cache.insert("long.example", RecordType::A, cname(), 60, None);

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    for domain in ["short.example", "long.example"] {
        assert!(cache.refresh_record(domain, &RecordType::A, None, cname(), None));
    }
    // Both are due by then and neither has expired.
    let due = coarse_clock::coarse_now_secs() + 25;

    assert!(
        cache
            .claim_due_refresh(&timer("short.example", due), due, &no_ranking())
            .is_none(),
        "a 30 s entry unasked since its renewal must not renew again"
    );
    assert!(
        cache
            .claim_due_refresh(&timer("long.example", due + 20), due + 20, &no_ranking())
            .is_some(),
        "a 60 s entry inside the access window renews as before"
    );

    assert!(cache.get("short.example", &RecordType::A).is_some());
    assert!(
        cache
            .claim_due_refresh(&timer("short.example", due), due, &no_ranking())
            .is_some(),
        "asked for again, the 30 s entry renews again"
    );
}

/// A hit on an entry whose timer is pending arms nothing more.
#[test]
fn test_hits_on_an_armed_entry_arm_no_second_timer() {
    let cache = cache(0.75, u64::MAX);
    let timers = wire_timers(&cache, 16);
    cache.insert("busy.example", RecordType::A, cname(), 300, None);
    for _ in 0..10 {
        assert!(cache.get("busy.example", &RecordType::A).is_some());
    }

    assert_eq!(drain(&timers).len(), 1);
}

/// A full inbox sheds the timer. The entry stays armed, so its hits do not
/// each try again while the inbox is full; compaction re-arms it once it is
/// overdue.
#[test]
fn test_shed_timer_is_rearmed_by_compaction_not_by_each_hit() {
    coarse_clock::tick();
    let cache = cache(0.5, u64::MAX);
    let timers = wire_timers(&cache, 1);
    // Due in half an hour, so compaction leaves it alone.
    cache.insert("first.example", RecordType::A, cname(), 3600, None);
    // Due a second in, so it is overdue when compaction runs.
    cache.insert("second.example", RecordType::A, cname(), 2, None);

    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        1,
        "the second timer found this thread's inbox full"
    );
    let delivered = drain(&timers);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].key.domain, "first.example");

    for _ in 0..5 {
        assert!(cache.get("second.example", &RecordType::A).is_some());
    }
    assert!(
        drain(&timers).is_empty(),
        "hits must not retry a shed timer"
    );

    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    cache.compact();
    let rearmed: Vec<String> = drain(&timers)
        .into_iter()
        .map(|timer| timer.key.domain.to_string())
        .collect();
    assert!(
        rearmed.contains(&"second.example".to_string()),
        "compaction must re-arm the shed entry once overdue: {rearmed:?}"
    );
}

#[test]
fn test_each_thread_gets_the_whole_inbox_capacity() {
    let cache = cache(0.75, u64::MAX);
    let timers = wire_timers(&cache, 100);
    for i in 0..100 {
        cache.insert(
            &format!("burst-{i}.example"),
            RecordType::A,
            cname(),
            300,
            None,
        );
    }

    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        0,
        "a burst on one thread may use all of its capacity"
    );
    assert_eq!(drain(&timers).len(), 100);
}

/// An expired entry still inside its stale grace is worth renewing: clients
/// are being served it. TTL 3 (grace 6 s) rather than 1: the coarse clock
/// moves in whole seconds, so a 2 s grace leaves no margin after a sleep.
#[test]
fn test_stale_entry_still_in_grace_is_claimed() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    cache.insert("stale.example", RecordType::A, cname(), 3, None);

    std::thread::sleep(Duration::from_millis(3_200));
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
    let timers = wire_timers(&cache, 16);
    cache.insert("failing.example", RecordType::A, cname(), 300, None);
    let armed = drain(&timers).remove(0);

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
        drain(&timers).is_empty(),
        "a hit must not turn a failing upstream into one retry per hit"
    );

    cache.compact();
    let rearmed = drain(&timers);
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
    let timers = wire_timers(&cache, 16);
    cache.insert("on-time.example", RecordType::A, cname(), 3600, None);
    drain(&timers);

    cache.compact();

    assert!(drain(&timers).is_empty());
}
