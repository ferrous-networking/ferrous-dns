use ferrous_dns_domain::config::dns::DnsConfig;

#[test]
fn test_config_default_values() {
    let config = DnsConfig::default();

    assert_eq!(config.query_timeout, 3);
    assert!(config.cache_enabled);
    assert_eq!(config.cache_ttl, 3600);
    assert!(!config.dnssec_enabled);
    assert_eq!(config.cache_max_entries, 200_000);
    assert_eq!(config.cache_eviction_strategy, "hit_rate");
    assert!(config.cache_optimistic_refresh);
    assert_eq!(config.cache_min_hit_rate, 2.0);
    assert_eq!(config.cache_min_frequency, 10);
    assert_eq!(config.cache_min_lfuk_score, 1.5);
    assert_eq!(config.cache_refresh_threshold, 0.75);
    assert_eq!(config.cache_lfuk_history_size, 10);
    assert!((config.cache_batch_eviction_percentage - 0.1).abs() < f64::EPSILON);
    assert_eq!(config.cache_compaction_interval, 300);
    assert!(!config.cache_adaptive_thresholds);
    assert_eq!(config.cache_access_window_secs, 7200);
    assert_eq!(config.cache_min_ttl, 0);
    assert_eq!(config.cache_max_ttl, 86_400);
    assert!(config.block_private_ptr);
    assert!(!config.block_non_fqdn);
    assert!(config.local_domain.is_none());
    assert!(config.local_dns_server.is_none());
    assert!(config.local_records.is_empty());
}

#[test]
fn test_config_cache_min_frequency_default() {
    let config = DnsConfig::default();
    assert_eq!(config.cache_min_frequency, 10);
}

#[test]
fn test_config_cache_min_lfuk_score_default() {
    let config = DnsConfig::default();
    assert_eq!(config.cache_min_lfuk_score, 1.5);
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
        cache_lfuk_history_size = 5
        cache_batch_eviction_percentage = 0.2
        cache_compaction_interval = 120
        cache_adaptive_thresholds = true
        cache_access_window_secs = 3600
        block_private_ptr = false
        block_non_fqdn = true
        local_domain = "home.lan"
        local_dns_server = "192.168.1.1:53"
    "#;

    let config: DnsConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(config.upstream_servers, vec!["8.8.8.8:53"]);
    assert_eq!(config.query_timeout, 5);
    assert_eq!(config.cache_ttl, 7200);
    assert_eq!(config.cache_max_entries, 100000);
    assert_eq!(config.cache_eviction_strategy, "lfu");
    assert!(!config.cache_optimistic_refresh);
    assert_eq!(config.cache_min_hit_rate, 3.0);
    assert_eq!(config.cache_min_frequency, 20);
    assert_eq!(config.cache_min_lfuk_score, 2.0);
    assert!(config.cache_adaptive_thresholds);
    assert_eq!(config.cache_access_window_secs, 3600);
    assert!(!config.block_private_ptr);
    assert!(config.block_non_fqdn);
    assert_eq!(config.local_domain, Some("home.lan".to_string()));
    assert_eq!(config.local_dns_server, Some("192.168.1.1:53".to_string()));
}

#[test]
fn test_local_domain_intercept_suffix_logic() {
    let local_domain = "lan";
    let suffix = format!(".{}", local_domain);

    assert!("device.lan".ends_with(&suffix));
    assert!("x.com.lan".ends_with(&suffix));
    assert!("deep.sub.device.lan".ends_with(&suffix));
    assert!(!"google.com".ends_with(&suffix));
    assert!(!"notlan".ends_with(&suffix));
    assert!(!"xlan".ends_with(&suffix));

    assert_eq!("lan", local_domain);
}
