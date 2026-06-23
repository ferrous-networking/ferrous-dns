//! Backward/forward compatibility of the backup `[dns64]` snapshot fields:
//! pre-0.9.2 backups carry no `dns64` section, so it must default to disabled
//! with no prefix, and the fields must round-trip when present.

use ferrous_dns_application::use_cases::backup::snapshot::SnapshotDns64Config;

#[test]
fn missing_dns64_keys_default_to_disabled() {
    let parsed: SnapshotDns64Config = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(!parsed.enabled);
    assert_eq!(parsed.prefix, None);
}

#[test]
fn dns64_fields_round_trip() {
    let parsed: SnapshotDns64Config =
        serde_json::from_value(serde_json::json!({"enabled": true, "prefix": "64:ff9b::/96"}))
            .unwrap();
    assert!(parsed.enabled);
    assert_eq!(parsed.prefix.as_deref(), Some("64:ff9b::/96"));

    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert_eq!(reserialized["enabled"], true);
    assert_eq!(reserialized["prefix"], "64:ff9b::/96");
}
