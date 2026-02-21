use ferrous_dns_infrastructure::dns::NegativeQueryTracker;
use std::sync::Arc;

#[test]
fn test_cleanup_removes_stale_entries() {
    let tracker = NegativeQueryTracker::with_config(60, 300, 5, 0);
    let domain: Arc<str> = Arc::from("stale.example");

    tracker.record_and_get_ttl(&domain);

    let stats_before = tracker.stats();
    assert_eq!(stats_before.total_domains, 1);

    let removed = tracker.cleanup_old_entries();
    assert_eq!(removed, 1);

    let stats_after = tracker.stats();
    assert_eq!(stats_after.total_domains, 0);
}

#[test]
fn test_cleanup_preserves_active_entries() {
    let tracker = NegativeQueryTracker::with_config(60, 300, 5, 9999);
    let domain: Arc<str> = Arc::from("active.example");

    tracker.record_and_get_ttl(&domain);

    let stats_before = tracker.stats();
    assert_eq!(stats_before.total_domains, 1);

    let removed = tracker.cleanup_old_entries();
    assert_eq!(removed, 0);

    let stats_after = tracker.stats();
    assert_eq!(stats_after.total_domains, 1);
}

#[test]
fn test_entry_count_decrements_after_cleanup() {
    let tracker = NegativeQueryTracker::with_config(60, 300, 2, 0);

    for i in 0..5u32 {
        let domain: Arc<str> = Arc::from(format!("domain{i}.example").as_str());
        tracker.record_and_get_ttl(&domain);
    }

    assert_eq!(tracker.stats().total_domains, 5);

    let removed = tracker.cleanup_old_entries();
    assert_eq!(removed, 5);
    assert_eq!(tracker.stats().total_domains, 0);
}
