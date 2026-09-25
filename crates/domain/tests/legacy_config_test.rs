//! Values earlier releases started with, loaded through the file path the
//! server uses at startup and on reload: parse, normalise, then validate.

use ferrous_dns_domain::config::CacheEvictionStrategy;
use ferrous_dns_domain::{Config, DomainError};

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

/// `MINIMAL_TOML` with `lines` added to `[dns]` and `tables` appended.
fn file(dns_lines: &str, tables: &str) -> String {
    format!(
        "{}\n{tables}\n",
        MINIMAL_TOML.replace("[dns]\n", &format!("[dns]\n{dns_lines}\n"))
    )
}

fn load(contents: &str) -> Config {
    let config = Config::from_toml_str(contents).expect("the file must load");
    config.validate().expect("the loaded config must validate");
    config
}

fn load_error(contents: &str) -> String {
    match Config::from_toml_str(contents).and_then(|config| config.validate()) {
        Err(DomainError::ConfigError(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

#[test]
fn a_hostname_bind_address_on_a_disabled_listener_is_ignored() {
    for tables in [
        "[server.encrypted_dns]\ndot_bind_address = \"localhost\"",
        "[server.encrypted_dns]\ndoq_enabled = false\ndoq_bind_address = \"localhost\"",
        "[server.encrypted_dns]\ndoh_bind_address = \"localhost\"\ndoh_port = 8443",
        // Without doh_port, DoH is served on the web listener and this key is unused.
        "[server.encrypted_dns]\ndoh_enabled = true\ndoh_bind_address = \"localhost\"",
    ] {
        let encrypted = load(&file("", tables)).server.encrypted_dns;
        assert_eq!(
            (
                encrypted.dot_bind_address,
                encrypted.doq_bind_address,
                encrypted.doh_bind_address
            ),
            (None, None, None),
            "{tables}"
        );
    }
}

#[test]
fn a_hostname_bind_address_on_a_running_listener_still_fails_to_load() {
    for (tables, key) in [
        (
            "[server.encrypted_dns]\ndot_enabled = true\ndot_bind_address = \"localhost\"",
            "dot_bind_address",
        ),
        (
            "[server.encrypted_dns]\ndoq_enabled = true\ndoq_bind_address = \"localhost\"",
            "doq_bind_address",
        ),
        (
            "[server.encrypted_dns]\ndoh_enabled = true\ndoh_port = 8443\ndoh_bind_address = \"localhost\"",
            "doh_bind_address",
        ),
    ] {
        let message = load_error(&file("", tables));
        assert!(message.contains(key), "{key}: {message}");
    }
}

#[test]
fn a_disabled_listener_keeps_a_valid_bind_address() {
    let tables = "[server.encrypted_dns]\ndot_bind_address = \"[::]\"";
    let encrypted = load(&file("", tables)).server.encrypted_dns;
    assert_eq!(encrypted.dot_bind_address, Some("::".parse().unwrap()));
}

#[test]
fn a_malformed_cookie_secret_is_ignored_while_cookies_are_disabled() {
    let tables = "[dns.dns_cookies]\nenabled = false\nserver_secret = \"changeme\"";
    let cookies = load(&file("", tables)).dns.dns_cookies;
    assert!(!cookies.enabled);
    assert_eq!(cookies.server_secret, None);
}

#[test]
fn a_malformed_cookie_secret_with_cookies_on_fails_saying_how_to_fix_it() {
    for tables in [
        "[dns.dns_cookies]\nserver_secret = \"changeme\"",
        "[dns.dns_cookies]\nenabled = true\nserver_secret = \"changeme\"",
    ] {
        let message = load_error(&file("", tables));
        assert!(
            message.contains("server_secret") && message.contains("openssl rand -hex 32"),
            "{tables}: {message}"
        );
    }
}

/// Older releases ran every name but `lfu` and `lfu-k` as hit_rate.
#[test]
fn an_unknown_cache_eviction_strategy_loads_as_hit_rate() {
    for name in ["hit-rate", "Hit-Rate", "fifo", ""] {
        let dns_lines = format!("cache_eviction_strategy = \"{name}\"");
        let config = load(&file(&dns_lines, ""));
        assert_eq!(
            config.dns.cache_eviction_strategy,
            CacheEvictionStrategy::HitRate,
            "{name:?}"
        );
    }
}

#[test]
fn a_local_dns_server_hostname_disables_local_forwarding() {
    for value in ["router.lan:53", "router.lan", ""] {
        let dns_lines = format!("local_dns_server = \"{value}\"");
        let config = load(&file(&dns_lines, ""));
        assert_eq!(config.dns.local_dns_server, None, "{value:?}");
        assert_eq!(config.dns.local_dns_server_addr().unwrap(), None);
    }
}

/// Older releases started with an upstream that had no host, and every query
/// to it failed; the file now loads without it, and without a pool it emptied.
#[test]
fn an_upstream_without_a_host_is_dropped() {
    let contents = format!(
        "{}\n{}",
        MINIMAL_TOML.replace(
            r#"upstream_servers = ["1.1.1.1:53"]"#,
            r#"upstream_servers = ["1.1.1.1:53", "tcp://:53"]"#,
        ),
        r#"
[[dns.pools]]
name = "mixed"
strategy = "Parallel"
servers = ["doq://:853", "doq://dns.adguard-dns.com:853", "udp://:53"]

[[dns.pools]]
name = "hostless"
strategy = "Failover"
servers = ["tls://:853"]
"#
    );
    let config = load(&contents);

    assert_eq!(config.dns.upstream_servers, ["1.1.1.1:53"]);
    let pools: Vec<(&str, &[String])> = config
        .dns
        .pools
        .iter()
        .map(|p| (p.name.as_str(), p.servers.as_slice()))
        .collect();
    assert_eq!(
        pools,
        [("mixed", &["doq://dns.adguard-dns.com:853".to_string()][..])]
    );
}

/// Older releases failed to start with these, so they still fail to parse.
#[test]
fn an_upstream_older_releases_rejected_is_kept_for_the_parser() {
    let tables = "[[dns.pools]]\nname = \"p\"\nstrategy = \"Parallel\"\nservers = [\"quic://dns.adguard-dns.com\"]";
    let config = load(&file("", tables));
    assert_eq!(config.dns.pools[0].servers, ["quic://dns.adguard-dns.com"]);
}

/// Older releases ran the retention job with 0: every run deletes every row.
#[test]
fn a_zero_query_log_retention_is_kept() {
    let config =
        load(&MINIMAL_TOML.replace("[database]\n", "[database]\nqueries_log_stored = 0\n"));
    assert_eq!(config.database.queries_log_stored, 0);
}

/// Whether the loaded config (first) holds the default (second) for the key under test.
type LoadsTheDefault = fn(&Config, &Config) -> bool;

/// Older releases ran with each of these, with the component it sizes broken
/// or off; the file now loads with the default instead.
#[test]
fn a_zero_older_releases_ran_with_loads_as_the_default() {
    let defaults = Config::default();
    let cases: [(&str, &str, LoadsTheDefault); 20] = [
        ("", "[dns]\nquery_timeout = 0", |c, d| {
            c.dns.query_timeout == d.dns.query_timeout
        }),
        ("", "[dns]\nquery_timeout = 9223372036854775807", |c, d| {
            c.dns.query_timeout == d.dns.query_timeout
        }),
        ("", "[dns]\ncache_max_entries = 0", |c, d| {
            c.dns.cache_max_entries == d.dns.cache_max_entries
        }),
        ("", "[dns]\ncache_eviction_sample_size = 0", |c, d| {
            c.dns.cache_eviction_sample_size == d.dns.cache_eviction_sample_size
        }),
        (
            "",
            "[dns]\ncache_optimistic_refresh = false\ncache_compaction_interval = 0",
            |c, d| c.dns.cache_compaction_interval == d.dns.cache_compaction_interval,
        ),
        (
            "",
            "[dns]\ncache_enabled = false\ncache_shard_amount = 6\ncache_inflight_shards = 1",
            |c, d| {
                c.dns.cache_shard_amount == d.dns.cache_shard_amount
                    && c.dns.cache_inflight_shards == d.dns.cache_inflight_shards
            },
        ),
        (
            "",
            "[dns]\ncache_enabled = false\ncache_min_ttl = 600\ncache_max_ttl = 300",
            |c, d| c.dns.cache_min_ttl == d.dns.cache_min_ttl && c.dns.cache_max_ttl == 300,
        ),
        ("", "[dns.health_check]\ntimeout = 0", |c, d| {
            c.dns.health_check.timeout == d.dns.health_check.timeout
        }),
        (
            "",
            "[dns.rate_limit]\nenabled = true\nqueries_per_second = 0\nburst_size = 0\nstale_entry_ttl_secs = 0",
            |c, d| {
                let (r, dr) = (&c.dns.rate_limit, &d.dns.rate_limit);
                (r.queries_per_second, r.burst_size, r.stale_entry_ttl_secs)
                    == (dr.queries_per_second, dr.burst_size, dr.stale_entry_ttl_secs)
            },
        ),
        ("", "[dns.tunneling_detection]\nstale_entry_ttl_secs = 0", |c, d| {
            c.dns.tunneling_detection.stale_entry_ttl_secs
                == d.dns.tunneling_detection.stale_entry_ttl_secs
        }),
        ("", "[dns.dga_detection]\nstale_entry_ttl_secs = 0", |c, d| {
            c.dns.dga_detection.stale_entry_ttl_secs == d.dns.dga_detection.stale_entry_ttl_secs
        }),
        (
            "",
            "[dns.nxdomain_hijack]\nenabled = false\nprobe_interval_secs = 0",
            |c, d| {
                c.dns.nxdomain_hijack.probe_interval_secs
                    == d.dns.nxdomain_hijack.probe_interval_secs
            },
        ),
        (
            "",
            "[dns.nxdomain_hijack]\nprobe_timeout_ms = 0\nhijack_ip_ttl_secs = 0",
            |c, d| {
                let (h, dh) = (&c.dns.nxdomain_hijack, &d.dns.nxdomain_hijack);
                (h.probe_timeout_ms, h.hijack_ip_ttl_secs)
                    == (dh.probe_timeout_ms, dh.hijack_ip_ttl_secs)
            },
        ),
        (
            "",
            "[dns.response_ip_filter]\nrefresh_interval_secs = 0\nip_ttl_secs = 0",
            |c, d| {
                let (f, df) = (&c.dns.response_ip_filter, &d.dns.response_ip_filter);
                (f.refresh_interval_secs, f.ip_ttl_secs)
                    == (df.refresh_interval_secs, df.ip_ttl_secs)
            },
        ),
        ("query_log_max_batch_size = 0", "", |c, d| {
            c.database.query_log_max_batch_size == d.database.query_log_max_batch_size
        }),
        ("", "[auth]\nsession_ttl_hours = 0\nremember_me_days = 0", |c, d| {
            (c.auth.session_ttl_hours, c.auth.remember_me_days)
                == (d.auth.session_ttl_hours, d.auth.remember_me_days)
        }),
        // Past year 9999 but addable to now: older releases stored an expiry
        // that the hourly cleanup deleted.
        ("", "[auth]\nremember_me_days = 3000000", |c, d| {
            c.auth.remember_me_days == d.auth.remember_me_days
        }),
        ("", "[auth]\nmfa_challenge_ttl_secs = 0", |c, d| {
            c.auth.mfa_challenge_ttl_secs == d.auth.mfa_challenge_ttl_secs
        }),
        ("", "[auth]\nmfa_challenge_ttl_secs = -60", |c, d| {
            c.auth.mfa_challenge_ttl_secs == d.auth.mfa_challenge_ttl_secs
        }),
        ("", "[auth]\nlogin_rate_limit_window_secs = 0", |c, d| {
            c.auth.login_rate_limit_window_secs == d.auth.login_rate_limit_window_secs
        }),
    ];
    for (database_lines, tables, loads_the_default) in cases {
        let contents = load_sections(database_lines, tables);
        let config = load(&contents);
        assert!(
            loads_the_default(&config, &defaults),
            "{database_lines}{tables}"
        );
    }
}

/// Older releases failed to start or panicked with each of these, so the file
/// still fails to load, naming the key.
#[test]
fn a_value_older_releases_failed_or_panicked_on_still_fails_to_load() {
    for (database_lines, tables, key) in [
        (
            "",
            "[dns.health_check]\ninterval = 0",
            "dns.health_check.interval",
        ),
        (
            "",
            "[dns]\ncache_compaction_interval = 0",
            "dns.cache_compaction_interval",
        ),
        (
            "",
            "[dns]\ncache_shard_amount = 6",
            "dns.cache_shard_amount",
        ),
        (
            "",
            "[dns]\ncache_inflight_shards = 1",
            "dns.cache_inflight_shards",
        ),
        (
            "",
            "[dns]\ncache_min_ttl = 600\ncache_max_ttl = 300",
            "dns.cache_min_ttl",
        ),
        (
            "",
            "[dns.nxdomain_hijack]\nprobe_interval_secs = 0",
            "dns.nxdomain_hijack.probe_interval_secs",
        ),
        (
            "query_log_channel_capacity = 0",
            "",
            "database.query_log_channel_capacity",
        ),
        (
            "client_channel_capacity = 0",
            "",
            "database.client_channel_capacity",
        ),
        (
            "query_log_flush_interval_ms = 0",
            "",
            "database.query_log_flush_interval_ms",
        ),
        (
            "write_pool_max_connections = 0",
            "",
            "database.write_pool_max_connections",
        ),
        (
            "query_log_pool_max_connections = 0",
            "",
            "database.query_log_pool_max_connections",
        ),
        (
            "read_pool_max_connections = 0",
            "",
            "database.read_pool_max_connections",
        ),
        (
            "write_busy_timeout_secs = 0",
            "",
            "database.write_busy_timeout_secs",
        ),
        (
            "read_acquire_timeout_secs = 0",
            "",
            "database.read_acquire_timeout_secs",
        ),
        (
            "wal_checkpoint_interval_secs = 0",
            "",
            "database.wal_checkpoint_interval_secs",
        ),
        // chrono cannot add these to now: older releases panicked at login.
        (
            "",
            "[auth]\nsession_ttl_hours = 4294967295",
            "auth.session_ttl_hours",
        ),
        (
            "",
            "[auth]\nmfa_challenge_ttl_secs = 9223372036854775807",
            "auth.mfa_challenge_ttl_secs",
        ),
    ] {
        let message = load_error(&load_sections(database_lines, tables));
        assert!(message.contains(key), "{key}: {message}");
    }
}

/// `MINIMAL_TOML` with `database_lines` added to `[database]` and `tables`
/// merged in: a `[dns]` header in `tables` extends the existing `[dns]`.
fn load_sections(database_lines: &str, tables: &str) -> String {
    let (dns_lines, tables) = match tables.strip_prefix("[dns]\n") {
        Some(dns_lines) => (dns_lines, ""),
        None => ("", tables),
    };
    file(dns_lines, tables).replace("[database]\n", &format!("[database]\n{database_lines}\n"))
}
