use ferrous_dns_domain::{ResponseIpFilterAction, ResponseIpFilterConfig};

// ── Defaults ─────────────────────────────────────────────────────────────────

#[test]
fn default_values_are_sane() {
    let config = ResponseIpFilterConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.action, ResponseIpFilterAction::Block);
    assert!(config.ip_list_urls.is_empty());
    assert_eq!(config.refresh_interval_secs, 86400);
    assert_eq!(config.ip_ttl_secs, 604800);
}

#[test]
fn default_action_is_block() {
    let config = ResponseIpFilterConfig::default();
    assert_eq!(config.action, ResponseIpFilterAction::Block);
}

#[test]
fn default_is_disabled() {
    let config = ResponseIpFilterConfig::default();
    assert!(!config.enabled);
}

// ── TOML deserialization ─────────────────────────────────────────────────────

#[test]
fn deserializes_empty_toml_with_defaults() {
    let config: ResponseIpFilterConfig = toml::from_str("").unwrap();
    assert!(!config.enabled);
    assert_eq!(config.refresh_interval_secs, 86400);
    assert_eq!(config.ip_ttl_secs, 604800);
}

#[test]
fn deserializes_partial_toml_preserves_defaults() {
    let toml = r#"
        enabled = true
        action = "alert"
    "#;
    let config: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.action, ResponseIpFilterAction::Alert);
    assert_eq!(config.refresh_interval_secs, 86400);
    assert_eq!(config.ip_ttl_secs, 604800);
}

#[test]
fn deserializes_block_action() {
    let toml = r#"action = "block""#;
    let config: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.action, ResponseIpFilterAction::Block);
}

#[test]
fn deserializes_alert_action() {
    let toml = r#"action = "alert""#;
    let config: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.action, ResponseIpFilterAction::Alert);
}

#[test]
fn deserializes_full_config() {
    let toml = r#"
        enabled = true
        action = "alert"
        ip_list_urls = ["https://example.com/ips.txt", "https://other.com/feed.txt"]
        refresh_interval_secs = 3600
        ip_ttl_secs = 86400
    "#;
    let config: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.action, ResponseIpFilterAction::Alert);
    assert_eq!(config.ip_list_urls.len(), 2);
    assert_eq!(config.refresh_interval_secs, 3600);
    assert_eq!(config.ip_ttl_secs, 86400);
}

#[test]
#[should_panic]
fn rejects_invalid_action() {
    let toml = r#"action = "drop""#;
    let _: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
}

// ── Serialization roundtrip ──────────────────────────────────────────────────

#[test]
fn serializes_and_deserializes_roundtrip() {
    let original = ResponseIpFilterConfig {
        enabled: true,
        action: ResponseIpFilterAction::Alert,
        ip_list_urls: vec!["https://example.com/ips.txt".to_string()],
        refresh_interval_secs: 3600,
        ip_ttl_secs: 86400,
    };
    let toml_str = toml::to_string(&original).unwrap();
    let restored: ResponseIpFilterConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(restored.enabled, original.enabled);
    assert_eq!(restored.action, original.action);
    assert_eq!(restored.ip_list_urls, original.ip_list_urls);
    assert_eq!(
        restored.refresh_interval_secs,
        original.refresh_interval_secs
    );
    assert_eq!(restored.ip_ttl_secs, original.ip_ttl_secs);
}

#[test]
fn empty_urls_roundtrip() {
    let original = ResponseIpFilterConfig::default();
    let toml_str = toml::to_string(&original).unwrap();
    let restored: ResponseIpFilterConfig = toml::from_str(&toml_str).unwrap();
    assert!(restored.ip_list_urls.is_empty());
}
