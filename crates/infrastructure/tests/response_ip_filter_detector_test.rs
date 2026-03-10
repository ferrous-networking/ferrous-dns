use ferrous_dns_application::ports::{ResponseIpFilterEvictionTarget, ResponseIpFilterStore};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::ResponseIpFilterConfig;
use ferrous_dns_infrastructure::dns::ResponseIpFilterDetector;

fn test_config() -> ResponseIpFilterConfig {
    ResponseIpFilterConfig {
        enabled: true,
        ip_ttl_secs: 1,
        ..Default::default()
    }
}

// ── ResponseIpFilterStore trait ──────────────────────────────────────────────

#[test]
fn unknown_ip_is_not_blocked() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "1.2.3.4".parse().unwrap();
    assert!(!detector.is_blocked_ip(&ip));
}

#[test]
fn inserted_ip_is_detected_as_blocked() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector.blocked_ips.insert(ip);
    detector.blocked_ip_confirmed_at.insert(ip, coarse_now_ns());
    assert!(detector.is_blocked_ip(&ip));
}

#[test]
fn multiple_ips_are_detected() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip1 = "203.0.113.1".parse().unwrap();
    let ip2 = "198.51.100.2".parse().unwrap();
    let now = coarse_now_ns();
    detector.blocked_ips.insert(ip1);
    detector.blocked_ip_confirmed_at.insert(ip1, now);
    detector.blocked_ips.insert(ip2);
    detector.blocked_ip_confirmed_at.insert(ip2, now);

    assert!(detector.is_blocked_ip(&ip1));
    assert!(detector.is_blocked_ip(&ip2));
    assert!(!detector.is_blocked_ip(&"10.0.0.1".parse().unwrap()));
}

#[test]
fn ipv6_address_is_detected() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "2001:db8::1".parse().unwrap();
    detector.blocked_ips.insert(ip);
    detector.blocked_ip_confirmed_at.insert(ip, coarse_now_ns());
    assert!(detector.is_blocked_ip(&ip));
}

#[test]
fn duplicate_insert_is_idempotent() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "203.0.113.1".parse().unwrap();
    detector.blocked_ips.insert(ip);
    detector.blocked_ips.insert(ip);
    assert_eq!(detector.blocked_ip_count(), 1);
}

// ── Eviction ─────────────────────────────────────────────────────────────────

#[test]
fn stale_ips_are_evicted() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    let stale_ns = coarse_now_ns() - 10_000_000_000;
    detector.blocked_ips.insert(ip);
    detector.blocked_ip_confirmed_at.insert(ip, stale_ns);

    assert!(detector.is_blocked_ip(&ip));
    detector.evict_stale_ips();
    assert!(!detector.is_blocked_ip(&ip));
    assert_eq!(detector.blocked_ip_count(), 0);
}

#[test]
fn fresh_ips_survive_eviction() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector.blocked_ips.insert(ip);
    detector.blocked_ip_confirmed_at.insert(ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(detector.is_blocked_ip(&ip));
    assert_eq!(detector.blocked_ip_count(), 1);
}

#[test]
fn mixed_stale_and_fresh_ips() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let stale_ip = "203.0.113.1".parse().unwrap();
    let fresh_ip = "203.0.113.2".parse().unwrap();
    let stale_ns = coarse_now_ns() - 10_000_000_000;

    detector.blocked_ips.insert(stale_ip);
    detector.blocked_ip_confirmed_at.insert(stale_ip, stale_ns);
    detector.blocked_ips.insert(fresh_ip);
    detector
        .blocked_ip_confirmed_at
        .insert(fresh_ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(!detector.is_blocked_ip(&stale_ip));
    assert!(detector.is_blocked_ip(&fresh_ip));
    assert_eq!(detector.blocked_ip_count(), 1);
}

#[test]
fn eviction_with_zero_ttl_removes_all() {
    let config = ResponseIpFilterConfig {
        ip_ttl_secs: 0,
        ..Default::default()
    };
    let detector = ResponseIpFilterDetector::new(&config);
    let ip1 = "10.0.0.1".parse().unwrap();
    let ip2 = "10.0.0.2".parse().unwrap();
    detector.blocked_ips.insert(ip1);
    detector.blocked_ip_confirmed_at.insert(ip1, 0);
    detector.blocked_ips.insert(ip2);
    detector.blocked_ip_confirmed_at.insert(ip2, 0);

    detector.evict_stale_ips();
    assert_eq!(detector.blocked_ip_count(), 0);
}

#[test]
fn eviction_on_empty_detector_is_noop() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    detector.evict_stale_ips();
    assert_eq!(detector.blocked_ip_count(), 0);
}

// ── blocked_ip_count ─────────────────────────────────────────────────────────

#[test]
fn blocked_ip_count_tracks_set_size() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    assert_eq!(detector.blocked_ip_count(), 0);

    let ip1 = "203.0.113.1".parse().unwrap();
    let ip2 = "203.0.113.2".parse().unwrap();
    detector.blocked_ips.insert(ip1);
    detector.blocked_ips.insert(ip2);
    assert_eq!(detector.blocked_ip_count(), 2);
}

// ── IP list parsing ──────────────────────────────────────────────────────────

#[test]
fn new_detector_has_empty_state() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    assert_eq!(detector.blocked_ip_count(), 0);
    assert!(!detector.is_blocked_ip(&"1.2.3.4".parse().unwrap()));
}
