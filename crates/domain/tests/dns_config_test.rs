use ferrous_dns_domain::config::dns::DnsConfig;

#[test]
fn test_qname_case_randomization_defaults_off_when_absent() {
    // Existing configs without the field must still deserialize, defaulting off.
    let config: DnsConfig = toml::from_str("query_timeout = 3").unwrap();
    assert!(!config.qname_case_randomization);
}

#[test]
fn test_qname_case_randomization_roundtrip() {
    let config: DnsConfig = toml::from_str("qname_case_randomization = true").unwrap();
    assert!(config.qname_case_randomization);

    let serialized = toml::to_string(&config).unwrap();
    let reparsed: DnsConfig = toml::from_str(&serialized).unwrap();
    assert!(reparsed.qname_case_randomization);
}

#[test]
fn test_mdns_enabled_defaults_off_when_absent() {
    // Existing configs without the field must still deserialize, defaulting off.
    let config: DnsConfig = toml::from_str("query_timeout = 3").unwrap();
    assert!(!config.mdns_enabled);
}

#[test]
fn test_mdns_enabled_roundtrip() {
    let config: DnsConfig = toml::from_str("mdns_enabled = true").unwrap();
    assert!(config.mdns_enabled);

    let serialized = toml::to_string(&config).unwrap();
    let reparsed: DnsConfig = toml::from_str(&serialized).unwrap();
    assert!(reparsed.mdns_enabled);
}

#[test]
fn test_config_deserialization_ignores_unknown_fields() {
    let toml_str = r#"
        cache_lazy_expiration = true
        conditional_forward_network = "10.0.0.0/8"
        conditional_forward_router = "10.0.0.1"
    "#;

    let config: Result<DnsConfig, _> = toml::from_str(toml_str);
    assert!(
        config.is_ok(),
        "Old config with removed fields should still deserialize: {:?}",
        config.err()
    );
}

#[test]
fn test_config_deserialization_with_all_fields() {
    let toml_str = r#"
        upstream_servers = ["8.8.8.8:53"]
        query_timeout = 5
        cache_enabled = true
        cache_ttl = 7200
        dnssec_enabled = false
        cache_max_entries = 100000
        cache_eviction_strategy = "lfu"
        cache_optimistic_refresh = false
        cache_min_hit_rate = 3.0
        cache_min_frequency = 20
        cache_min_lfuk_score = 2.0
        cache_refresh_threshold = 0.5
        cache_batch_eviction_percentage = 0.2
        cache_compaction_interval = 120
        cache_access_window_secs = 3600
        block_private_ptr = false
        block_non_fqdn = true
        mdns_enabled = true
        local_domain = "home.lan"
        local_dns_server = "192.168.1.1:53"
    "#;

    let config: DnsConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(config.upstream_servers, vec!["8.8.8.8:53"]);
    assert_eq!(config.query_timeout, 5);
    assert_eq!(config.cache_ttl, 7200);
    assert_eq!(config.cache_max_entries, 100000);
    assert_eq!(
        config.cache_eviction_strategy,
        ferrous_dns_domain::config::CacheEvictionStrategy::Lfu
    );
    assert!(!config.cache_optimistic_refresh);
    assert_eq!(config.cache_min_hit_rate, 3.0);
    assert_eq!(config.cache_min_frequency, 20);
    assert_eq!(config.cache_min_lfuk_score, 2.0);
    assert_eq!(config.cache_access_window_secs, 3600);
    assert!(!config.block_private_ptr);
    assert!(config.block_non_fqdn);
    assert!(config.mdns_enabled);
    assert_eq!(config.local_domain, Some("home.lan".to_string()));
    assert_eq!(config.local_dns_server, Some("192.168.1.1:53".to_string()));
}

#[test]
fn test_removed_cache_max_refresh_per_sec_key_is_ignored() {
    // Config files written before this key was retired must keep loading.
    let toml_str = r#"
        query_timeout = 3
        cache_max_refresh_per_sec = 4.0
    "#;

    let config: DnsConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(config.query_timeout, 3);
}
