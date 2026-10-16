//! What happens when a refresh timer fires: whether the cache hands the entry
//! to the worker, and what it arms next.
//!
//! An entry inside the access window is claimed, one outside it is parked
//! until a hit brings it back (with the timer that removes it once it dies),
//! a permanent entry never is, a claimed entry is not claimed twice, a timer
//! that is no longer the entry's claims nothing, and hot entries rank before
//! cold ones.

#[path = "support/refresh.rs"]
mod refresh;

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::{coarse_clock, CacheKey};
use ferrous_dns_infrastructure::dns::{
    CachedData, ColdThresholds, DnsCache, DnsCacheConfig, ScheduledRefresh, TimerInbox, TimerKind,
};
use refresh::{
    address, cname, drain, no_ranking, refresh_cache, refresh_cache_config, wire_timers,
};
use std::collections::BinaryHeap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const IP: &str = "192.0.2.9";

fn cache(refresh_threshold: f64, access_window_secs: u64) -> Arc<DnsCache> {
    refresh_cache(100, refresh_threshold, access_window_secs)
}

/// The latest timer the cache armed for `domain`, taken from `inbox` along
/// with every other timer there.
fn armed(inbox: &TimerInbox, domain: &str) -> ScheduledRefresh {
    armed_all(inbox, &[domain]).remove(0)
}

/// The latest timer armed for each of `domains`, from one drain of `inbox`.
fn armed_all(inbox: &TimerInbox, domains: &[&str]) -> Vec<ScheduledRefresh> {
    let timers = drain(inbox);
    domains
        .iter()
        .map(|domain| {
            timers
                .iter()
                .rev()
                .find(|timer| timer.key.domain == *domain)
                .cloned()
                .unwrap_or_else(|| panic!("no timer armed for {domain}: {timers:?}"))
        })
        .collect()
}

/// Lets the coarse clock move on by `secs`.
fn wait_secs(secs: u64) {
    std::thread::sleep(Duration::from_millis(secs * 1_000 + 100));
    coarse_clock::tick();
}

#[test]
fn test_insert_arms_a_timer_for_the_second_the_entry_falls_due() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    let now = coarse_clock::coarse_now_secs();

    cache.insert("armed.example", RecordType::A, address(IP), 3600, None);

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
fn test_permanent_entries_arm_nothing_and_negative_ones_only_their_expiry() {
    let cache = cache(0.0, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    let now = coarse_clock::coarse_now_secs();

    cache.insert_permanent("local.example", RecordType::A, address(IP), 300);
    cache.insert(
        "missing.example",
        RecordType::A,
        CachedData::NegativeResponse,
        300,
        None,
    );

    let armed = drain(&timers);
    assert_eq!(armed.len(), 1, "only the negative entry arms: {armed:?}");
    assert_eq!(armed[0].kind, TimerKind::NegativeExpiry);
    assert_eq!(armed[0].key.domain, "missing.example");
    assert!(
        (now + 300..=now + 301).contains(&armed[0].due_at_secs),
        "a negative entry's timer fires when it expires"
    );
    let now = now + 1;
    let fired = ScheduledRefresh {
        due_at_secs: now,
        key: CacheKey::new("local.example", RecordType::A),
        kind: TimerKind::Due,
    };
    assert!(
        cache
            .claim_due_refresh(&fired, now, &no_ranking())
            .is_none(),
        "a local record is never renewed"
    );
    assert!(
        cache.is_permanent("local.example", &RecordType::A),
        "nor removed"
    );
}

/// With optimistic refresh off, an insert arms only the timer that removes
/// the entry once it dies, and no insert or hit leaves it with a timer that
/// could claim it.
#[test]
fn test_without_optimistic_refresh_only_the_expiry_is_armed() {
    coarse_clock::tick();
    let cache = DnsCache::new(DnsCacheConfig {
        renew_ahead: false,
        ..refresh_cache_config(100, 0.0, u64::MAX)
    });
    let (timers, _stale) = wire_timers(&cache);
    let inserted = coarse_clock::coarse_now_secs();

    cache.insert("plain.example", RecordType::A, cname(), 300, None);
    wait_secs(1);
    assert!(cache.get("plain.example", &RecordType::A).is_some());

    let armed = drain(&timers);
    assert_eq!(armed.len(), 1, "one timer, the expiry: {armed:?}");
    assert!(
        (inserted + 600..=inserted + 601).contains(&armed[0].due_at_secs),
        "it dies at the end of its stale grace, two TTLs after insertion; got {} from {inserted}",
        armed[0].due_at_secs
    );

    let now = coarse_clock::coarse_now_secs();
    for due_at_secs in inserted..=now + 1 {
        let fired = ScheduledRefresh {
            due_at_secs,
            key: CacheKey::new("plain.example", RecordType::A),
            kind: TimerKind::Due,
        };
        assert!(
            cache
                .claim_due_refresh(&fired, now + 1, &no_ranking())
                .is_none(),
            "no timer is pending, so none fired at {due_at_secs} claims the entry"
        );
    }
    assert_eq!(cache.len(), 1, "and none removes a live entry");
}

#[test]
fn test_due_entry_inside_the_access_window_is_claimed_once() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("due.example", RecordType::A, address(IP), 300, None);
    let timer = armed(&timers, "due.example");

    let first = cache.claim_due_refresh(&timer, timer.due_at_secs, &no_ranking());
    let second = cache.claim_due_refresh(&timer, timer.due_at_secs, &no_ranking());

    assert!(first.is_some(), "the due entry must be claimed");
    assert!(
        second.is_none(),
        "a claimed entry must not be claimed again"
    );
}

/// Only the timer the entry has pending counts: one for another second, or
/// for a key no longer cached, claims nothing.
#[test]
fn test_timer_that_is_not_the_entrys_pending_one_claims_nothing() {
    coarse_clock::tick();
    let cache = cache(0.75, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("early.example", RecordType::A, address(IP), 3600, None);
    let pending = armed(&timers, "early.example");
    let now = coarse_clock::coarse_now_secs();

    for due_at_secs in [now + 10, pending.due_at_secs - 1, pending.due_at_secs + 1] {
        let other = ScheduledRefresh {
            due_at_secs,
            ..pending.clone()
        };
        assert!(cache
            .claim_due_refresh(&other, pending.due_at_secs, &no_ranking())
            .is_none());
    }
    let gone = ScheduledRefresh {
        key: CacheKey::new("gone.example", RecordType::A),
        ..pending.clone()
    };
    assert!(cache
        .claim_due_refresh(&gone, pending.due_at_secs, &no_ranking())
        .is_none());
    assert!(
        cache
            .claim_due_refresh(&pending, pending.due_at_secs, &no_ranking())
            .is_some(),
        "the pending timer itself still claims the entry"
    );
}

/// The timer of an entry that was renewed since, by a serve-stale repair or
/// a newer insert, is stale: that renewal armed the live one.
#[test]
fn test_timer_of_an_entry_renewed_since_claims_nothing() {
    coarse_clock::tick();
    let cache = cache(0.5, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("renewed.example", RecordType::A, address(IP), 300, None);
    let first = armed(&timers, "renewed.example");

    wait_secs(1);
    assert!(cache.refresh_record(
        "renewed.example",
        &RecordType::A,
        Some(300),
        address(IP),
        None
    ));
    let renewed = armed(&timers, "renewed.example");

    assert!(renewed.due_at_secs > first.due_at_secs);
    assert!(
        cache
            .claim_due_refresh(&first, renewed.due_at_secs, &no_ranking())
            .is_none(),
        "the old timer must not renew the entry a second time"
    );
    assert!(cache
        .claim_due_refresh(&renewed, renewed.due_at_secs, &no_ranking())
        .is_some());
}

/// Storing over an entry whose renewal is in flight replaces the record and
/// its timer: the old renewal's claim does not carry over.
#[test]
fn test_insert_over_an_entry_being_renewed_arms_the_new_one() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("raced.example", RecordType::A, cname(), 300, None);
    let first = armed(&timers, "raced.example");
    assert!(cache
        .claim_due_refresh(&first, first.due_at_secs, &no_ranking())
        .is_some());
    assert!(cache.start_claimed_refresh(&first.key, first.due_at_secs));

    wait_secs(1);
    cache.insert("raced.example", RecordType::A, cname(), 300, None);
    let second = armed(&timers, "raced.example");

    let claim = cache.claim_due_refresh(&second, second.due_at_secs, &no_ranking());
    assert!(claim.is_some(), "the stored record has its own timer");
    assert!(
        cache.start_claimed_refresh(&second.key, second.due_at_secs),
        "and is not marked in flight by the old renewal"
    );
}

/// An entry nobody asked for within the access window is parked when its
/// timer fires, with the timer that removes it once it dies, and the next
/// hit arms a new renewal, due at once.
#[test]
fn test_entry_outside_the_access_window_rearms_on_its_next_hit() {
    coarse_clock::tick();
    let cache = cache(0.0, 0);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("idle.example", RecordType::A, cname(), 300, None);
    let timer = armed(&timers, "idle.example");
    let inserted = timer.due_at_secs - 1;

    wait_secs(1);
    let now = coarse_clock::coarse_now_secs();
    assert!(
        cache
            .claim_due_refresh(&timer, now, &no_ranking())
            .is_none(),
        "an entry idle past the access window is not renewed"
    );
    let expiry = armed(&timers, "idle.example");
    assert_eq!(
        expiry.due_at_secs,
        inserted + 600,
        "parked, it keeps the timer that removes it once it dies"
    );
    assert!(
        cache
            .claim_due_refresh(&expiry, now, &no_ranking())
            .is_none(),
        "that timer never claims a renewal"
    );
    assert!(drain(&timers).is_empty(), "nor is anything else armed");

    assert!(cache.get("idle.example", &RecordType::A).is_some());
    let rearmed = armed(&timers, "idle.example");
    assert!(
        rearmed.due_at_secs <= now,
        "already due, so it fires at once"
    );
    assert!(
        cache
            .claim_due_refresh(&rearmed, now, &no_ranking())
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
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("short.example", RecordType::A, cname(), 30, None);
    cache.insert("long.example", RecordType::A, cname(), 60, None);

    wait_secs(1);
    for domain in ["short.example", "long.example"] {
        assert!(cache.refresh_record(domain, &RecordType::A, None, cname(), None));
    }
    let renewed = armed_all(&timers, &["short.example", "long.example"]);
    let (short, long) = (&renewed[0], &renewed[1]);

    assert!(
        cache
            .claim_due_refresh(short, short.due_at_secs, &no_ranking())
            .is_none(),
        "a 30 s entry unasked since its renewal must not renew again"
    );
    assert!(
        cache
            .claim_due_refresh(long, long.due_at_secs, &no_ranking())
            .is_some(),
        "a 60 s entry inside the access window renews unasked"
    );

    assert!(cache.get("short.example", &RecordType::A).is_some());
    let rearmed = armed(&timers, "short.example");
    assert!(
        cache
            .claim_due_refresh(&rearmed, short.due_at_secs, &no_ranking())
            .is_some(),
        "asked for again, the 30 s entry renews again"
    );
}

/// A hit on an entry whose timer is pending arms nothing more.
#[test]
fn test_hits_on_an_armed_entry_arm_no_second_timer() {
    let cache = cache(0.75, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("busy.example", RecordType::A, cname(), 300, None);
    for _ in 0..10 {
        assert!(cache.get("busy.example", &RecordType::A).is_some());
    }

    assert_eq!(drain(&timers).len(), 1);
}

/// The inbox never turns a timer away, so a burst that lands on one thread
/// loses none: an entry without its timer would never be renewed nor removed.
#[test]
fn test_a_burst_on_one_thread_loses_no_timer() {
    let cache = cache(0.75, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    for i in 0..10_000 {
        cache.insert(
            &format!("burst-{i}.example"),
            RecordType::A,
            cname(),
            300,
            None,
        );
    }

    assert_eq!(drain(&timers).len(), 10_000);
}

/// An expired entry still inside its stale grace is worth renewing: clients
/// are being served it. TTL 3 (grace 6 s) rather than 1: the coarse clock
/// moves in whole seconds, so a 2 s grace leaves no margin after a sleep.
#[test]
fn test_stale_entry_still_in_grace_is_claimed() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("stale.example", RecordType::A, cname(), 3, None);
    let timer = armed(&timers, "stale.example");

    wait_secs(3);
    let now = coarse_clock::coarse_now_secs();

    assert!(cache
        .claim_due_refresh(&timer, now, &no_ranking())
        .is_some());
}

/// A claimed renewal whose entry died waiting for a permit is given up,
/// counted as shed, and the dead entry removed.
#[test]
fn test_claim_whose_entry_died_waiting_is_counted_as_shed() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("late.example", RecordType::A, cname(), 300, None);
    let timer = armed(&timers, "late.example");
    assert!(cache
        .claim_due_refresh(&timer, timer.due_at_secs, &no_ranking())
        .is_some());

    // Past the end of its stale grace (inserted + 2 × TTL).
    assert!(!cache.start_claimed_refresh(&timer.key, timer.due_at_secs + 600));
    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        1
    );
    assert!(cache.is_empty(), "the dead entry is removed");
    assert!(
        !cache.start_claimed_refresh(&timer.key, timer.due_at_secs),
        "the claim was given up"
    );
}

/// A claim waiting for a permit does not keep a client served stale from
/// queueing its own repair, and the claim then stands down. The repair may
/// already be past arming the entry's next timer, so standing down arms one:
/// otherwise a repair that failed would leave the entry with none.
#[test]
fn test_claim_waiting_for_a_permit_does_not_block_a_stale_repair() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let (timers, mut stale) = wire_timers(&cache);
    cache.insert("waiting.example", RecordType::A, cname(), 3, None);
    let timer = armed(&timers, "waiting.example");
    assert!(cache
        .claim_due_refresh(&timer, timer.due_at_secs, &no_ranking())
        .is_some());

    wait_secs(3);
    assert!(cache.get("waiting.example", &RecordType::A).is_some());

    let repair = stale.try_recv();
    assert!(
        repair.is_ok(),
        "the stale hit must queue a repair: {repair:?}"
    );
    assert!(
        !cache.start_claimed_refresh(&timer.key, coarse_clock::coarse_now_secs()),
        "the repair is in flight, so the claim must not resolve too"
    );

    let next = armed(&timers, "waiting.example");
    // TTL 3: it dies 6 s after insertion, before the 300 s retry interval.
    let inserted = timer.due_at_secs - 1;
    assert_eq!(next.kind, TimerKind::Due);
    assert_eq!(next.due_at_secs, inserted + 6);
    assert!(
        cache
            .claim_due_refresh(&next, next.due_at_secs - 1, &no_ranking())
            .is_some(),
        "the armed timer is the entry's pending renewal"
    );
}

#[test]
fn test_due_renewals_rank_hot_before_cold() {
    coarse_clock::tick();
    let cache = cache(0.0, u64::MAX);
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("cold.example", RecordType::A, cname(), 300, None);
    cache.insert("hot.example", RecordType::A, cname(), 300, None);
    for _ in 0..5 {
        assert!(cache.get("hot.example", &RecordType::A).is_some());
    }
    let thresholds = ColdThresholds {
        min_hit_rate: 0.0,
        min_frequency: 3,
    };

    let mut due = BinaryHeap::new();
    for timer in armed_all(&timers, &["cold.example", "hot.example"]) {
        due.push(
            cache
                .claim_due_refresh(&timer, timer.due_at_secs, &thresholds)
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
    let (timers, _stale) = wire_timers(&cache);
    cache.insert("renewed.example", RecordType::A, cname(), 300, None);
    cache.insert("untouched.example", RecordType::A, cname(), 300, None);
    for _ in 0..5 {
        assert!(cache.get("renewed.example", &RecordType::A).is_some());
        assert!(cache.get("untouched.example", &RecordType::A).is_some());
    }
    assert!(cache.refresh_record("renewed.example", &RecordType::A, Some(300), cname(), None));
    let thresholds = ColdThresholds {
        min_hit_rate: 2.0,
        min_frequency: 0,
    };

    let mut due = BinaryHeap::new();
    for timer in armed_all(&timers, &["renewed.example", "untouched.example"]) {
        due.push(
            cache
                .claim_due_refresh(&timer, timer.due_at_secs, &thresholds)
                .expect("both are due"),
        );
    }

    assert_eq!(due.pop().unwrap().key.domain, "untouched.example");
    assert_eq!(due.pop().unwrap().key.domain, "renewed.example");
}
