use ferrous_dns_application::ports::TunnelingFlagStore;
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_application::use_cases::dns::TunnelingAnalysisEvent;
use ferrous_dns_domain::{RecordType, TunnelingDetectionConfig};
use ferrous_dns_infrastructure::dns::tunneling::client_stats::{ClientApexStats, TrackingKey};
use ferrous_dns_infrastructure::dns::tunneling::detector::TunnelingAlert;
use ferrous_dns_infrastructure::dns::TunnelingDetector;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn test_config() -> TunnelingDetectionConfig {
    TunnelingDetectionConfig {
        enabled: true,
        confidence_threshold: 0.5,
        entropy_threshold: 3.0,
        query_rate_per_apex: 10,
        unique_subdomain_threshold: 5,
        txt_proportion_threshold: 0.05,
        nxdomain_ratio_threshold: 0.20,
        stale_entry_ttl_secs: 1,
        ..Default::default()
    }
}

fn make_event(domain: &str, record_type: RecordType, nxdomain: bool) -> TunnelingAnalysisEvent {
    TunnelingAnalysisEvent {
        domain: Arc::from(domain),
        record_type,
        client_ip: "192.168.1.1".parse().unwrap(),
        was_nxdomain: nxdomain,
    }
}

// ── TunnelingFlagStore trait ────────────────────────────────────────────────

#[test]
fn flagged_domain_is_detected_by_store() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    let alert = TunnelingAlert {
        signal: "entropy".to_string(),
        measured_value: 4.5,
        threshold: 3.8,
        confidence: 0.8,
        timestamp_ns: coarse_now_ns(),
    };
    detector
        .flagged_domains
        .insert(Arc::from("evil.com"), alert);
    assert!(detector.is_flagged("sub.evil.com"));
    assert!(detector.is_flagged("evil.com"));
}

#[test]
fn unflagged_domain_passes() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    assert!(!detector.is_flagged("safe.example.com"));
}

#[test]
fn flagged_domain_check_extracts_apex() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    detector.flagged_domains.insert(
        Arc::from("malware.net"),
        TunnelingAlert {
            signal: "query_rate".to_string(),
            measured_value: 100.0,
            threshold: 50.0,
            confidence: 0.9,
            timestamp_ns: coarse_now_ns(),
        },
    );
    assert!(detector.is_flagged("deep.sub.malware.net"));
    assert!(!detector.is_flagged("malware.org"));
}

// ── Eviction ────────────────────────────────────────────────────────────────

#[test]
fn stale_entries_are_evicted() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    let stale_ns = coarse_now_ns() - 10_000_000_000;
    let key = TrackingKey {
        subnet: 0,
        apex_hash: 12345,
    };
    detector.stats.insert(key, ClientApexStats::new(stale_ns));
    detector
        .stats
        .get(&key)
        .unwrap()
        .last_seen_ns
        .store(stale_ns, Ordering::Relaxed);

    assert_eq!(detector.tracked_count(), 1);
    detector.evict_stale();
    assert_eq!(detector.tracked_count(), 0);
}

#[test]
fn fresh_entries_survive_eviction() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    let key = TrackingKey {
        subnet: 0,
        apex_hash: 99999,
    };
    detector
        .stats
        .insert(key, ClientApexStats::new(coarse_now_ns()));

    assert_eq!(detector.tracked_count(), 1);
    detector.evict_stale();
    assert_eq!(detector.tracked_count(), 1);
}

#[test]
fn stale_flagged_domains_are_evicted() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    let stale_ns = coarse_now_ns() - 10_000_000_000;
    detector.flagged_domains.insert(
        Arc::from("old-evil.com"),
        TunnelingAlert {
            signal: "entropy".to_string(),
            measured_value: 4.0,
            threshold: 3.8,
            confidence: 0.8,
            timestamp_ns: stale_ns,
        },
    );

    assert_eq!(detector.flagged_count(), 1);
    detector.evict_stale();
    assert_eq!(detector.flagged_count(), 0);
}

#[test]
fn fresh_flagged_domains_survive_eviction() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    detector.flagged_domains.insert(
        Arc::from("recent-evil.com"),
        TunnelingAlert {
            signal: "entropy".to_string(),
            measured_value: 4.0,
            threshold: 3.8,
            confidence: 0.8,
            timestamp_ns: coarse_now_ns(),
        },
    );

    detector.evict_stale();
    assert_eq!(detector.flagged_count(), 1);
}

// ── Confidence scoring ──────────────────────────────────────────────────────

#[test]
fn confidence_scoring_combines_signals() {
    let config = test_config();
    let (detector, _tx, _rx) = TunnelingDetector::new(&config);

    let client_ip: IpAddr = "192.168.1.1".parse().unwrap();
    for i in 0..20 {
        let domain = format!("a3f8d2e1b7c4{i}.evil.com");
        let event = TunnelingAnalysisEvent {
            domain: Arc::from(domain.as_str()),
            record_type: RecordType::TXT,
            client_ip,
            was_nxdomain: i % 3 == 0,
        };
        detector.process_event(&event);
    }

    assert!(
        detector.is_flagged("anything.evil.com"),
        "expected evil.com to be flagged after multiple suspicious signals"
    );
}

#[test]
fn normal_queries_do_not_trigger_flagging() {
    let config = test_config();
    let (detector, _tx, _rx) = TunnelingDetector::new(&config);

    for _ in 0..5 {
        detector.process_event(&make_event("www.example.com", RecordType::A, false));
    }

    assert!(
        !detector.is_flagged("www.example.com"),
        "normal browsing should not flag the domain"
    );
}

#[test]
fn high_entropy_alone_does_not_flag_with_high_confidence_threshold() {
    let config = TunnelingDetectionConfig {
        enabled: true,
        confidence_threshold: 0.7,
        entropy_threshold: 3.0,
        query_rate_per_apex: 1000,
        unique_subdomain_threshold: 1000,
        ..Default::default()
    };
    let (detector, _tx, _rx) = TunnelingDetector::new(&config);

    detector.process_event(&make_event(
        "a3f8d2e1b7c4a9f0.example.com",
        RecordType::A,
        false,
    ));

    assert!(
        !detector.is_flagged("example.com"),
        "single signal should not reach 0.7 confidence"
    );
}

#[test]
fn nxdomain_ratio_contributes_to_confidence() {
    let config = test_config();
    let (detector, _tx, _rx) = TunnelingDetector::new(&config);

    for i in 0..15 {
        let domain = format!("xf9a2c{i}e7b1d.nxtest.com");
        detector.process_event(&make_event(&domain, RecordType::TXT, true));
    }

    assert!(
        detector.is_flagged("nxtest.com"),
        "high NXDOMAIN ratio + entropy + rate should flag domain"
    );
}

#[test]
fn txt_proportion_contributes_to_confidence() {
    let config = test_config();
    let (detector, _tx, _rx) = TunnelingDetector::new(&config);

    for i in 0..15 {
        let domain = format!("c4d8f2a{i}b3e7.txttest.com");
        detector.process_event(&make_event(&domain, RecordType::TXT, false));
    }

    assert!(
        detector.is_flagged("txttest.com"),
        "high TXT proportion + entropy + rate should flag domain"
    );
}

// ── process_event ───────────────────────────────────────────────────────────

#[test]
fn process_event_increments_query_count() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    detector.process_event(&make_event("sub.example.com", RecordType::A, false));

    assert_eq!(detector.tracked_count(), 1);
}

#[test]
fn different_apex_domains_create_separate_entries() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());
    detector.process_event(&make_event("sub.example.com", RecordType::A, false));
    detector.process_event(&make_event("sub.other.org", RecordType::A, false));

    assert_eq!(detector.tracked_count(), 2);
}

#[test]
fn different_clients_create_separate_entries() {
    let (detector, _tx, _rx) = TunnelingDetector::new(&test_config());

    let event1 = TunnelingAnalysisEvent {
        domain: Arc::from("sub.example.com"),
        record_type: RecordType::A,
        client_ip: "192.168.1.1".parse().unwrap(),
        was_nxdomain: false,
    };
    let event2 = TunnelingAnalysisEvent {
        domain: Arc::from("sub.example.com"),
        record_type: RecordType::A,
        client_ip: "10.0.0.1".parse().unwrap(),
        was_nxdomain: false,
    };

    detector.process_event(&event1);
    detector.process_event(&event2);

    assert_eq!(detector.tracked_count(), 2);
}

// ── Analysis loop ───────────────────────────────────────────────────────────

#[tokio::test]
async fn analysis_loop_processes_events_from_channel() {
    let config = test_config();
    let (detector, tx, rx) = TunnelingDetector::new(&config);
    let detector = Arc::new(detector);
    let detector_clone = Arc::clone(&detector);

    let handle = tokio::spawn(async move {
        detector_clone.run_analysis_loop(rx).await;
    });

    let client_ip: IpAddr = "192.168.1.1".parse().unwrap();
    for i in 0..20 {
        let domain = format!("a3f8d2e1b7c4{i}.evil.com");
        tx.send(TunnelingAnalysisEvent {
            domain: Arc::from(domain.as_str()),
            record_type: RecordType::TXT,
            client_ip,
            was_nxdomain: i % 3 == 0,
        })
        .await
        .unwrap();
    }

    drop(tx);
    handle.await.unwrap();

    assert!(detector.is_flagged("evil.com"));
}
