//! The certificates the TLS listeners loaded, as `/metrics` and the dashboard read them.

use ferrous_dns_application::tls_certificates::{LoadedCertificates, TlsListener};

#[test]
fn test_nothing_is_reported_before_a_listener_loads_a_certificate() {
    let loaded = LoadedCertificates::default();
    assert!(loaded.expiries().is_empty());
    assert_eq!(loaded.not_after(TlsListener::Web), None);
}

#[test]
fn test_recorded_listeners_come_back_in_a_stable_order() {
    let loaded = LoadedCertificates::default();
    loaded.record(TlsListener::Doq, 300);
    loaded.record(TlsListener::Web, 100);

    assert_eq!(
        loaded.expiries(),
        [(TlsListener::Web, 100), (TlsListener::Doq, 300)]
    );
    assert_eq!(loaded.not_after(TlsListener::Dot), None);
}

#[test]
fn test_the_first_record_for_a_listener_wins() {
    let loaded = LoadedCertificates::default();
    loaded.record(TlsListener::Dot, 100);
    loaded.record(TlsListener::Dot, 200);

    assert_eq!(loaded.not_after(TlsListener::Dot), Some(100));
}

#[test]
fn test_labels_name_the_listener() {
    let labels: Vec<_> = TlsListener::ALL.iter().map(|l| l.label()).collect();
    assert_eq!(labels, ["web", "dot", "doq"]);
}
