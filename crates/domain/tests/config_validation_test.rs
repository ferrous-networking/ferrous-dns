use ferrous_dns_domain::{Config, DomainError};

/// A config that passes every check, so a failure can only come from the
/// setting under test.
fn valid_config() -> Config {
    let mut config = Config::default();
    config.dns.upstream_servers = vec!["1.1.1.1:53".to_string()];
    config
}

fn validation_message(config: &Config) -> String {
    match config.validate() {
        Err(DomainError::ConfigError(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

const MINIMAL_TOML: &str = r#"
[server]
dns_port = 53
web_port = 8080
bind_address = "0.0.0.0"

[dns]
upstream_servers = ["1.1.1.1:53"]

[blocking]
enabled = true

[logging]
level = "info"

[database]
"#;

#[test]
fn a_valid_config_passes() {
    valid_config().validate().unwrap();
}

#[test]
fn a_minimal_file_parses_into_a_valid_config_with_a_default_pool() {
    let config = Config::from_toml_str(MINIMAL_TOML).unwrap();
    config.validate().unwrap();
    assert_eq!(config.dns.pools.len(), 1);
    assert_eq!(config.dns.pools[0].servers, ["1.1.1.1:53"]);
}

#[test]
fn the_builtin_config_is_valid() {
    let config = Config::builtin();
    config.validate().unwrap();
    assert!(!config.dns.pools.is_empty());
}

#[test]
fn a_parse_error_is_a_config_error() {
    assert!(matches!(
        Config::from_toml_str("[server"),
        Err(DomainError::ConfigError(_))
    ));
}

#[test]
fn a_dns64_table_without_enabled_parses_as_disabled() {
    let config = Config::from_toml_str(&format!(
        "{MINIMAL_TOML}\n[dns64]\nprefix = \"64:ff9b::/96\"\n"
    ))
    .unwrap();
    assert!(!config.dns64.enabled);
    assert_eq!(config.dns64.prefix, "64:ff9b::/96");
}

type BreakConfig = fn(&mut Config);

#[test]
fn values_that_panic_spin_or_disable_a_component_are_rejected_naming_the_key() {
    let cases: [(&str, BreakConfig); 40] = [
        ("dns.query_timeout", |c| c.dns.query_timeout = 0),
        ("dns.cache_max_entries", |c| c.dns.cache_max_entries = 0),
        ("dns.cache_compaction_interval", |c| {
            c.dns.cache_compaction_interval = 0
        }),
        ("dns.cache_eviction_sample_size", |c| {
            c.dns.cache_eviction_sample_size = 0
        }),
        ("dns.health_check.interval", |c| {
            c.dns.health_check.interval = 0
        }),
        ("dns.health_check.timeout", |c| {
            c.dns.health_check.timeout = 0
        }),
        ("dns.rate_limit.queries_per_second", |c| {
            c.dns.rate_limit.queries_per_second = 0
        }),
        ("dns.rate_limit.burst_size", |c| {
            c.dns.rate_limit.burst_size = 0
        }),
        ("dns.rate_limit.stale_entry_ttl_secs", |c| {
            c.dns.rate_limit.stale_entry_ttl_secs = 0
        }),
        ("dns.tunneling_detection.stale_entry_ttl_secs", |c| {
            c.dns.tunneling_detection.stale_entry_ttl_secs = 0
        }),
        ("dns.tunneling_detection.query_rate_per_apex", |c| {
            c.dns.tunneling_detection.query_rate_per_apex = 0
        }),
        ("dns.tunneling_detection.unique_subdomain_threshold", |c| {
            c.dns.tunneling_detection.unique_subdomain_threshold = 0
        }),
        ("dns.nxdomain_hijack.probe_interval_secs", |c| {
            c.dns.nxdomain_hijack.probe_interval_secs = 0
        }),
        ("dns.nxdomain_hijack.probe_timeout_ms", |c| {
            c.dns.nxdomain_hijack.probe_timeout_ms = 0
        }),
        ("dns.nxdomain_hijack.hijack_ip_ttl_secs", |c| {
            c.dns.nxdomain_hijack.hijack_ip_ttl_secs = 0
        }),
        ("dns.nxdomain_hijack.probes_per_round", |c| {
            c.dns.nxdomain_hijack.probes_per_round = 0
        }),
        ("dns.response_ip_filter.refresh_interval_secs", |c| {
            c.dns.response_ip_filter.refresh_interval_secs = 0
        }),
        ("dns.response_ip_filter.ip_ttl_secs", |c| {
            c.dns.response_ip_filter.ip_ttl_secs = 0
        }),
        ("dns.dga_detection.stale_entry_ttl_secs", |c| {
            c.dns.dga_detection.stale_entry_ttl_secs = 0
        }),
        ("dns.dga_detection.dga_rate_per_client", |c| {
            c.dns.dga_detection.dga_rate_per_client = 0
        }),
        ("database.query_log_channel_capacity", |c| {
            c.database.query_log_channel_capacity = 0
        }),
        ("database.query_log_max_batch_size", |c| {
            c.database.query_log_max_batch_size = 0
        }),
        ("database.query_log_flush_interval_ms", |c| {
            c.database.query_log_flush_interval_ms = 0
        }),
        ("database.client_channel_capacity", |c| {
            c.database.client_channel_capacity = 0
        }),
        ("database.write_pool_max_connections", |c| {
            c.database.write_pool_max_connections = 0
        }),
        ("database.query_log_pool_max_connections", |c| {
            c.database.query_log_pool_max_connections = 0
        }),
        ("database.read_pool_max_connections", |c| {
            c.database.read_pool_max_connections = 0
        }),
        ("database.write_busy_timeout_secs", |c| {
            c.database.write_busy_timeout_secs = 0
        }),
        ("database.read_acquire_timeout_secs", |c| {
            c.database.read_acquire_timeout_secs = 0
        }),
        ("database.wal_checkpoint_interval_secs", |c| {
            c.database.wal_checkpoint_interval_secs = 0
        }),
        ("auth.session_ttl_hours", |c| c.auth.session_ttl_hours = 0),
        ("auth.remember_me_days", |c| c.auth.remember_me_days = 0),
        ("auth.login_rate_limit_window_secs", |c| {
            c.auth.login_rate_limit_window_secs = 0
        }),
        ("auth.mfa_challenge_ttl_secs", |c| {
            c.auth.mfa_challenge_ttl_secs = -1
        }),
        ("dns.cache_shard_amount", |c| c.dns.cache_shard_amount = 0),
        ("dns.cache_shard_amount", |c| c.dns.cache_shard_amount = 1),
        ("dns.cache_shard_amount", |c| c.dns.cache_shard_amount = 12),
        ("dns.cache_inflight_shards", |c| {
            c.dns.cache_inflight_shards = 0
        }),
        ("dns.cache_inflight_shards", |c| {
            c.dns.cache_inflight_shards = 24
        }),
        ("dns.cache_min_ttl", |c| {
            c.dns.cache_min_ttl = 600;
            c.dns.cache_max_ttl = 60
        }),
    ];
    for (field, break_it) in cases {
        let mut config = valid_config();
        break_it(&mut config);
        let message = validation_message(&config);
        assert!(
            message.contains(field),
            "{field}: the message should name the key: {message}"
        );
    }
}

#[test]
fn zero_where_zero_has_a_meaning_is_accepted() {
    let mut config = valid_config();
    config.dns.cache_min_ttl = 0;
    config.dns.rate_limit.slip_ratio = 0;
    config.dns.rate_limit.tcp_max_connections_per_ip = 0;
    config.database.wal_autocheckpoint = 0;
    config.database.queries_log_stored = 0;
    config.database.sqlite_mmap_size_mb = 0;
    config.database.read_busy_timeout_secs = 0;
    config.auth.login_rate_limit_attempts = 0;
    config.blocking.block_ttl = 0;
    config.validate().unwrap();
}

/// These used to panic at login or at startup (and release builds abort on panic).
#[test]
fn values_whose_derived_duration_overflows_are_rejected_naming_the_key() {
    let cases: [(&str, BreakConfig); 4] = [
        ("auth.session_ttl_hours", |c| {
            c.auth.session_ttl_hours = u32::MAX
        }),
        ("auth.remember_me_days", |c| {
            c.auth.remember_me_days = u32::MAX
        }),
        ("auth.mfa_challenge_ttl_secs", |c| {
            c.auth.mfa_challenge_ttl_secs = i64::MAX
        }),
        ("dns.query_timeout", |c| {
            c.dns.query_timeout = u64::MAX / 1000 + 1
        }),
    ];
    for (field, break_it) in cases {
        let mut config = valid_config();
        break_it(&mut config);
        let message = validation_message(&config);
        assert!(
            message.contains(field),
            "{field}: the message should name the key: {message}"
        );
    }
}

#[test]
fn long_but_representable_durations_are_accepted() {
    let mut config = valid_config();
    // About 114 and 2,700 years: absurd, but chrono can add them to now.
    config.auth.session_ttl_hours = 1_000_000;
    config.auth.remember_me_days = 1_000_000;
    config.auth.mfa_challenge_ttl_secs = 86_400 * 365 * 1_000;
    config.dns.query_timeout = u64::MAX / 1000;
    config.validate().unwrap();
}

/// Auth timestamps are compared as strings in SQL: a year past 9999 renders as
/// `+10000-…`, sorts before today, and cleanup would delete it as expired.
#[test]
fn expiries_past_year_9999_are_rejected_naming_the_key() {
    // About 8,200 years: representable by chrono, but not as a four-digit year.
    let cases: [(&str, BreakConfig); 2] = [
        ("auth.remember_me_days", |c| {
            c.auth.remember_me_days = 3_000_000
        }),
        ("auth.mfa_challenge_ttl_secs", |c| {
            c.auth.mfa_challenge_ttl_secs = 86_400 * 365 * 8_200
        }),
    ];
    for (field, break_it) in cases {
        let mut config = valid_config();
        break_it(&mut config);
        let message = validation_message(&config);
        assert!(
            message.contains(field) && message.contains("9999"),
            "{field}: the message should name the key and the limit: {message}"
        );
    }
}

/// Older builds saved a bare router IP, which must still boot as port 53.
#[test]
fn a_local_dns_server_is_an_ip_with_port_53_unless_one_is_given() {
    for (value, addr) in [
        ("192.168.1.1:5353", "192.168.1.1:5353"),
        ("192.168.1.1", "192.168.1.1:53"),
        ("[fe80::1]:53", "[fe80::1]:53"),
        ("fe80::1", "[fe80::1]:53"),
    ] {
        let mut config = valid_config();
        config.dns.local_dns_server = Some(value.to_string());
        config.validate().unwrap();
        assert_eq!(
            config.dns.local_dns_server_addr().unwrap(),
            Some(addr.parse().unwrap()),
            "{value}"
        );
    }
}

#[test]
fn a_local_dns_server_must_be_an_ip_address() {
    let mut config = valid_config();
    for bad in ["router.lan:53", "router.lan", ""] {
        config.dns.local_dns_server = Some(bad.to_string());
        assert!(
            validation_message(&config).contains("dns.local_dns_server"),
            "{bad:?} should be rejected"
        );
    }
}
