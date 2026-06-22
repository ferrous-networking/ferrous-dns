//! Backward/forward compatibility of the backup [dns] snapshot DNSSEC fields:
//! pre-0.9 backups carried `dnssec_enabled` (bool); 0.9+ carry `dnssec_mode`.
//! Both must deserialize, and the new mode must round-trip.

use ferrous_dns_application::use_cases::backup::snapshot::SnapshotDnsConfig;

/// A complete [dns] snapshot section minus the DNSSEC keys (filled per test).
fn base_dns() -> serde_json::Value {
    serde_json::json!({
        "upstream_servers": [],
        "cache_enabled": true,
        "cache_eviction_strategy": "lfu",
        "cache_max_entries": 1000,
        "cache_min_hit_rate": 0.3,
        "cache_min_frequency": 10,
        "cache_min_lfuk_score": 1.5,
        "cache_compaction_interval": 300,
        "cache_refresh_threshold": 0.8,
        "cache_optimistic_refresh": true,
        "cache_adaptive_thresholds": true,
        "cache_access_window_secs": 7200,
        "cache_min_ttl": 0,
        "cache_max_ttl": 86400,
        "block_non_fqdn": false,
        "block_private_ptr": true,
        "local_domain": null,
        "local_dns_server": null
    })
}

fn with_keys(extra: serde_json::Value) -> serde_json::Value {
    let mut v = base_dns();
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

#[test]
fn legacy_dnssec_enabled_deserializes() {
    let parsed: SnapshotDnsConfig =
        serde_json::from_value(with_keys(serde_json::json!({"dnssec_enabled": true}))).unwrap();
    assert_eq!(parsed.dnssec_mode, None);
    assert_eq!(parsed.dnssec_enabled, Some(true));
}

#[test]
fn missing_dnssec_keys_default_to_none() {
    let parsed: SnapshotDnsConfig = serde_json::from_value(base_dns()).unwrap();
    assert_eq!(parsed.dnssec_mode, None);
    assert_eq!(parsed.dnssec_enabled, None);
}

#[test]
fn dnssec_mode_round_trips() {
    let parsed: SnapshotDnsConfig =
        serde_json::from_value(with_keys(serde_json::json!({"dnssec_mode": "strict"}))).unwrap();
    assert_eq!(parsed.dnssec_mode.as_deref(), Some("strict"));

    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert_eq!(reserialized["dnssec_mode"], "strict");
}
