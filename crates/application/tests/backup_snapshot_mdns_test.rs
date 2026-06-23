//! The backup [dns] snapshot must carry `mdns_enabled`: older backups predate the
//! field and must import as `false` (serde default), and the flag must round-trip
//! when set.

use ferrous_dns_application::use_cases::backup::snapshot::SnapshotDnsConfig;

/// A complete [dns] snapshot section minus `mdns_enabled` (added per test).
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

#[test]
fn missing_mdns_enabled_defaults_to_false() {
    // Older backups carry no `mdns_enabled` key; import must default it off.
    let parsed: SnapshotDnsConfig = serde_json::from_value(base_dns()).unwrap();
    assert!(!parsed.mdns_enabled);
}

#[test]
fn mdns_enabled_round_trips() {
    let mut v = base_dns();
    v["mdns_enabled"] = serde_json::json!(true);

    let parsed: SnapshotDnsConfig = serde_json::from_value(v).unwrap();
    assert!(parsed.mdns_enabled);

    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert_eq!(reserialized["mdns_enabled"], true);
}
