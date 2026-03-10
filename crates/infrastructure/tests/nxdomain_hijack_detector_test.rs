use ferrous_dns_application::ports::{NxdomainHijackIpStore, NxdomainHijackProbeTarget};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::NxdomainHijackConfig;
use ferrous_dns_infrastructure::dns::NxdomainHijackDetector;
use std::sync::Arc;

fn test_config() -> NxdomainHijackConfig {
    NxdomainHijackConfig {
        enabled: true,
        hijack_ip_ttl_secs: 1,
        ..Default::default()
    }
}

// ── NxdomainHijackIpStore trait ───────────────────────────────────────────────

#[test]
fn unknown_ip_is_not_hijack() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "1.2.3.4".parse().unwrap();
    assert!(!detector.is_hijack_ip(&ip));
}

#[test]
fn inserted_ip_is_detected_as_hijack() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector.hijack_ips.insert(ip);
    detector.hijack_ip_confirmed_at.insert(ip, coarse_now_ns());
    assert!(detector.is_hijack_ip(&ip));
}

#[test]
fn multiple_ips_are_detected() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip1 = "203.0.113.1".parse().unwrap();
    let ip2 = "198.51.100.2".parse().unwrap();
    let now = coarse_now_ns();
    detector.hijack_ips.insert(ip1);
    detector.hijack_ip_confirmed_at.insert(ip1, now);
    detector.hijack_ips.insert(ip2);
    detector.hijack_ip_confirmed_at.insert(ip2, now);

    assert!(detector.is_hijack_ip(&ip1));
    assert!(detector.is_hijack_ip(&ip2));
    assert!(!detector.is_hijack_ip(&"10.0.0.1".parse().unwrap()));
}

// ── Eviction ──────────────────────────────────────────────────────────────────

#[test]
fn stale_ips_are_evicted() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    let stale_ns = coarse_now_ns() - 10_000_000_000;
    detector.hijack_ips.insert(ip);
    detector.hijack_ip_confirmed_at.insert(ip, stale_ns);

    assert!(detector.is_hijack_ip(&ip));
    detector.evict_stale_ips();
    assert!(!detector.is_hijack_ip(&ip));
    assert_eq!(detector.hijack_ip_count(), 0);
}

#[test]
fn fresh_ips_survive_eviction() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector.hijack_ips.insert(ip);
    detector.hijack_ip_confirmed_at.insert(ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(detector.is_hijack_ip(&ip));
    assert_eq!(detector.hijack_ip_count(), 1);
}

#[test]
fn mixed_stale_and_fresh_ips() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let stale_ip = "203.0.113.1".parse().unwrap();
    let fresh_ip = "203.0.113.2".parse().unwrap();
    let stale_ns = coarse_now_ns() - 10_000_000_000;

    detector.hijack_ips.insert(stale_ip);
    detector.hijack_ip_confirmed_at.insert(stale_ip, stale_ns);
    detector.hijack_ips.insert(fresh_ip);
    detector
        .hijack_ip_confirmed_at
        .insert(fresh_ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(!detector.is_hijack_ip(&stale_ip));
    assert!(detector.is_hijack_ip(&fresh_ip));
    assert_eq!(detector.hijack_ip_count(), 1);
}

// ── Upstream tracking ─────────────────────────────────────────────────────────

#[test]
fn hijacking_upstream_count_reflects_state() {
    let detector = NxdomainHijackDetector::new(&test_config());

    assert_eq!(detector.hijacking_upstream_count(), 0);

    detector
        .upstream_hijacking
        .insert(Arc::from("udp://1.1.1.1:53"), true);
    assert_eq!(detector.hijacking_upstream_count(), 1);

    detector
        .upstream_hijacking
        .insert(Arc::from("udp://8.8.8.8:53"), false);
    assert_eq!(detector.hijacking_upstream_count(), 1);

    detector
        .upstream_hijacking
        .insert(Arc::from("udp://9.9.9.9:53"), true);
    assert_eq!(detector.hijacking_upstream_count(), 2);
}

#[test]
fn recovered_upstream_reduces_count() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let key: Arc<str> = Arc::from("udp://1.1.1.1:53");
    detector.upstream_hijacking.insert(Arc::clone(&key), true);
    assert_eq!(detector.hijacking_upstream_count(), 1);

    detector.upstream_hijacking.insert(key, false);
    assert_eq!(detector.hijacking_upstream_count(), 0);
}

// ── hijack_ip_count ───────────────────────────────────────────────────────────

#[test]
fn hijack_ip_count_tracks_set_size() {
    let detector = NxdomainHijackDetector::new(&test_config());
    assert_eq!(detector.hijack_ip_count(), 0);

    let ip1 = "203.0.113.1".parse().unwrap();
    let ip2 = "203.0.113.2".parse().unwrap();
    detector.hijack_ips.insert(ip1);
    detector.hijack_ips.insert(ip2);
    assert_eq!(detector.hijack_ip_count(), 2);
}
