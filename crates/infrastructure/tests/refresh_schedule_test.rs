//! When an entry falls due for renewal, and the timer store that holds it
//! until then.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::{
    refresh_due_at, CacheKey, RefreshSchedule, ScheduledRefresh, REFRESH_LEAD_SECS,
};

const INSERTED: u64 = 1_000_000;

fn due_offset(ttl: u32, threshold: f64) -> u64 {
    refresh_due_at(INSERTED, ttl, threshold) - INSERTED
}

fn timer(domain: &str, due_at_secs: u64, retry: bool) -> ScheduledRefresh {
    ScheduledRefresh {
        due_at_secs,
        key: CacheKey::new(domain, RecordType::A),
        retry,
    }
}

#[test]
fn test_long_ttl_falls_due_at_the_threshold() {
    assert_eq!(due_offset(3600, 0.75), 2700);
    assert_eq!(due_offset(86_400, 0.75), 64_800);
}

/// Whichever comes first: past 240 s of TTL the threshold leaves more than
/// the lead, below it the lead does.
#[test]
fn test_lead_wins_once_the_threshold_leaves_less_than_a_minute() {
    assert_eq!(due_offset(240, 0.75), 180);
    assert_eq!(due_offset(200, 0.75), 200 - REFRESH_LEAD_SECS);
    assert_eq!(due_offset(120, 0.75), 60);
}

/// Without the half-TTL bound a TTL just above the lead would be renewed
/// every second or so, each renewal bringing the same TTL back.
#[test]
fn test_lead_never_pulls_the_renewal_before_half_the_ttl() {
    assert_eq!(due_offset(100, 0.75), 50);
    assert_eq!(due_offset(61, 0.75), 31);
}

#[test]
fn test_ttl_within_the_lead_falls_due_at_the_threshold() {
    assert_eq!(due_offset(60, 0.75), 45);
    assert_eq!(due_offset(30, 0.75), 22);
    assert_eq!(due_offset(4, 0.75), 3);
}

#[test]
fn test_due_is_never_the_second_of_insertion() {
    assert_eq!(due_offset(300, 0.0), 1);
    assert_eq!(due_offset(1, 0.75), 1);
}

#[test]
fn test_threshold_out_of_range_is_clamped() {
    assert_eq!(due_offset(3600, 2.0), 3600 - REFRESH_LEAD_SECS);
    assert_eq!(due_offset(3600, -1.0), 1);
}

/// Across every TTL: the renewal falls after insertion, no later than the
/// expiry, no later than the threshold, and the lead never pulls it before
/// half the TTL when the threshold alone would have waited longer.
#[test]
fn test_due_invariants_hold_for_every_ttl() {
    for threshold in [0.0, 0.5, 0.75, 0.9, 1.0] {
        for ttl in (1..=86_400u32).step_by(7) {
            let ttl_secs = u64::from(ttl);
            let offset = due_offset(ttl, threshold);
            let proportional = (ttl_secs as f64 * threshold) as u64;
            assert!(offset >= 1, "ttl {ttl} threshold {threshold}: {offset}");
            assert!(
                offset <= ttl_secs,
                "ttl {ttl} threshold {threshold}: {offset}"
            );
            assert!(
                offset <= proportional.max(1),
                "ttl {ttl} threshold {threshold}: {offset} after the threshold"
            );
            assert!(
                offset >= proportional.min(ttl_secs.div_ceil(2)).max(1),
                "ttl {ttl} threshold {threshold}: {offset} before half the TTL"
            );
            if ttl_secs > REFRESH_LEAD_SECS {
                assert!(
                    offset <= (ttl_secs - REFRESH_LEAD_SECS).max(ttl_secs.div_ceil(2)),
                    "ttl {ttl} threshold {threshold}: {offset} leaves under a minute"
                );
            }
        }
    }
}

#[test]
fn test_take_due_returns_what_is_due_earliest_first() {
    let mut schedule = RefreshSchedule::default();
    schedule.register(timer("late.example", 30, false));
    schedule.register(timer("early.example", 10, false));
    schedule.register(timer("retry.example", 20, true));
    schedule.register(timer("future.example", 31, false));

    let due = schedule.take_due(30);

    let order: Vec<(&str, bool)> = due
        .iter()
        .map(|timer| (timer.key.domain.as_str(), timer.retry))
        .collect();
    assert_eq!(
        order,
        vec![
            ("early.example", false),
            ("retry.example", true),
            ("late.example", false)
        ]
    );
    assert_eq!(schedule.len(), 1);
    assert!(schedule.take_due(30).is_empty(), "taken timers are gone");
    assert_eq!(schedule.take_due(31).len(), 1);
    assert!(schedule.is_empty());
}

#[test]
fn test_timers_due_in_the_same_second_are_all_taken() {
    let mut schedule = RefreshSchedule::default();
    for i in 0..1_000 {
        schedule.register(timer(&format!("same-{i}.example"), 42, false));
    }

    assert!(schedule.take_due(41).is_empty());
    assert_eq!(schedule.take_due(42).len(), 1_000);
}

#[test]
fn test_retain_drops_rejected_timers_and_keeps_the_count() {
    let mut schedule = RefreshSchedule::default();
    for i in 0..10u64 {
        schedule.register(timer(&format!("t-{i}.example"), i, i % 3 == 0));
    }

    schedule.retain(|key| key.domain.ends_with("2.example") || key.domain.ends_with("3.example"));

    assert_eq!(schedule.len(), 2);
    let due: Vec<String> = schedule
        .take_due(u64::MAX)
        .into_iter()
        .map(|timer| timer.key.domain.to_string())
        .collect();
    assert_eq!(due, vec!["t-2.example", "t-3.example"]);
}
