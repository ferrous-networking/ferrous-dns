use ferrous_dns_domain::{Config, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::repositories::config_persistence::save_config_to_file;

fn default_config_toml() -> &'static str {
    r#"
[server]
dns_port = 53
web_port = 8080
bind_address = "0.0.0.0"
pihole_compat = false

[server.web_tls]
enabled = false
tls_cert_path = "/data/cert.pem"
tls_key_path = "/data/key.pem"

[dns]
upstream_servers = []
query_timeout = 3
default_strategy = "Parallel"
dnssec_enabled = true
cache_enabled = true
cache_ttl = 3600
cache_min_ttl = 0
cache_max_ttl = 86400
cache_max_entries = 10000
cache_eviction_strategy = "lfu"
cache_optimistic_refresh = true
cache_min_hit_rate = 0.3
cache_min_frequency = 10
cache_min_lfuk_score = 1.5
cache_refresh_threshold = 0.75
cache_lfuk_history_size = 10
cache_batch_eviction_percentage = 0.1
cache_compaction_interval = 300
cache_adaptive_thresholds = false
cache_access_window_secs = 7200
block_private_ptr = true
block_non_fqdn = true
local_domain = "lan"
local_dns_server = "10.0.0.1:53"

[[dns.pools]]
name = "primary"
strategy = "Parallel"
priority = 1
servers = ["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"]

[[dns.pools]]
name = "fallback"
strategy = "Failover"
priority = 2
servers = ["doq://dns.adguard-dns.com:853"]

[dns.health_check]
interval = 30
timeout = 2000
failure_threshold = 3
success_threshold = 2

[blocking]
enabled = true
custom_blocked = []
whitelist = []

[logging]
level = "info"

[database]
path = "ferrous-dns.db"
log_queries = true
queries_log_stored = 30
client_tracking_interval = 60
query_log_channel_capacity = 10000
query_log_max_batch_size = 2000
query_log_flush_interval_ms = 200
query_log_sample_rate = 1
client_channel_capacity = 4096
write_pool_max_connections = 3
read_pool_max_connections = 8
write_busy_timeout_secs = 30
read_busy_timeout_secs = 15
read_acquire_timeout_secs = 15
wal_autocheckpoint = 0

[auth]
enabled = false
session_ttl_hours = 24
remember_me_days = 30
login_rate_limit_attempts = 5
login_rate_limit_window_secs = 300

[auth.admin]
username = "admin"
"#
}

fn load_config(input: &str) -> Config {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("load.toml");
    std::fs::write(&path, input).unwrap();
    Config::load(Some(path.to_str().unwrap()), Default::default()).unwrap()
}

fn save_and_reparse(config: &Config, input: &str) -> toml_edit::DocumentMut {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.toml");
    std::fs::write(&path, input).unwrap();

    save_config_to_file(config, path.to_str().unwrap()).unwrap();

    let output = std::fs::read_to_string(&path).unwrap();
    output.parse::<toml_edit::DocumentMut>().unwrap()
}

// ── Pool serialization ───────────────────────────────────────────────────

#[test]
fn test_save_pools_writes_all_fields() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "test-pool".to_string(),
        strategy: UpstreamStrategy::Balanced,
        priority: 3,
        servers: vec![
            "https://dns.google/dns-query".to_string(),
            "https://cloudflare-dns.com/dns-query".to_string(),
        ],
        weight: Some(10),
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let dns = doc.get("dns").unwrap().as_table().unwrap();
    let pools = dns
        .get("pools")
        .expect("pools key must exist")
        .as_array_of_tables()
        .expect("pools must be array of tables");

    assert_eq!(pools.len(), 1);

    let pool = pools.iter().next().unwrap();
    assert_eq!(pool.get("name").unwrap().as_str().unwrap(), "test-pool");
    assert_eq!(pool.get("strategy").unwrap().as_str().unwrap(), "Balanced");
    assert_eq!(pool.get("priority").unwrap().as_integer().unwrap(), 3);
    assert_eq!(pool.get("weight").unwrap().as_integer().unwrap(), 10);

    let servers = pool.get("servers").unwrap().as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(
        servers.get(0).unwrap().as_str().unwrap(),
        "https://dns.google/dns-query"
    );
}

#[test]
fn test_save_pools_without_weight_omits_field() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "no-weight".to_string(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["https://example.com".to_string()],
        weight: None,
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let dns = doc.get("dns").unwrap().as_table().unwrap();
    let pool = dns
        .get("pools")
        .unwrap()
        .as_array_of_tables()
        .unwrap()
        .iter()
        .next()
        .unwrap();

    assert!(pool.get("weight").is_none());
}

#[test]
fn test_save_multiple_pools_preserves_order() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![
        UpstreamPool {
            name: "first".to_string(),
            strategy: UpstreamStrategy::Parallel,
            priority: 1,
            servers: vec!["https://a.example.com".to_string()],
            weight: None,
        },
        UpstreamPool {
            name: "second".to_string(),
            strategy: UpstreamStrategy::Failover,
            priority: 2,
            servers: vec!["https://b.example.com".to_string()],
            weight: None,
        },
        UpstreamPool {
            name: "third".to_string(),
            strategy: UpstreamStrategy::Balanced,
            priority: 3,
            servers: vec!["https://c.example.com".to_string()],
            weight: None,
        },
    ];

    let doc = save_and_reparse(&config, default_config_toml());
    let dns = doc.get("dns").unwrap().as_table().unwrap();
    let pools = dns.get("pools").unwrap().as_array_of_tables().unwrap();

    assert_eq!(pools.len(), 3);

    let names: Vec<&str> = pools
        .iter()
        .map(|p| p.get("name").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["first", "second", "third"]);
}

#[test]
fn test_save_empty_pools_removes_section() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![];

    let doc = save_and_reparse(&config, default_config_toml());
    let dns = doc.get("dns").unwrap().as_table().unwrap();

    assert!(dns.get("pools").is_none());
}

// ── Pool strategy roundtrip ──────────────────────────────────────────────

#[test]
fn test_pool_strategy_parallel_roundtrips() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "p".to_string(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["https://example.com".to_string()],
        weight: None,
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let pool = doc
        .get("dns")
        .unwrap()
        .as_table()
        .unwrap()
        .get("pools")
        .unwrap()
        .as_array_of_tables()
        .unwrap()
        .iter()
        .next()
        .unwrap();

    assert_eq!(pool.get("strategy").unwrap().as_str().unwrap(), "Parallel");
}

#[test]
fn test_pool_strategy_failover_roundtrips() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "f".to_string(),
        strategy: UpstreamStrategy::Failover,
        priority: 1,
        servers: vec!["https://example.com".to_string()],
        weight: None,
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let pool = doc
        .get("dns")
        .unwrap()
        .as_table()
        .unwrap()
        .get("pools")
        .unwrap()
        .as_array_of_tables()
        .unwrap()
        .iter()
        .next()
        .unwrap();

    assert_eq!(pool.get("strategy").unwrap().as_str().unwrap(), "Failover");
}

#[test]
fn test_pool_strategy_balanced_roundtrips() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "b".to_string(),
        strategy: UpstreamStrategy::Balanced,
        priority: 1,
        servers: vec!["https://example.com".to_string()],
        weight: None,
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let pool = doc
        .get("dns")
        .unwrap()
        .as_table()
        .unwrap()
        .get("pools")
        .unwrap()
        .as_array_of_tables()
        .unwrap()
        .iter()
        .next()
        .unwrap();

    assert_eq!(pool.get("strategy").unwrap().as_str().unwrap(), "Balanced");
}

// ── Adjacent sections preserved ──────────────────────────────────────────

#[test]
fn test_save_pools_preserves_health_check() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "new".to_string(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["https://example.com".to_string()],
        weight: None,
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let dns = doc.get("dns").unwrap().as_table().unwrap();

    let hc = dns
        .get("health_check")
        .expect("health_check must survive pool update");
    let hc_table = hc.as_table().expect("health_check must be a table");
    assert_eq!(hc_table.get("interval").unwrap().as_integer().unwrap(), 30);
    assert_eq!(hc_table.get("timeout").unwrap().as_integer().unwrap(), 2000);
    assert_eq!(
        hc_table
            .get("failure_threshold")
            .unwrap()
            .as_integer()
            .unwrap(),
        3
    );
}

#[test]
fn test_save_pools_preserves_upstream_servers() {
    let mut config = load_config(default_config_toml());
    config.dns.upstream_servers = vec!["https://fallback.example.com".to_string()];
    config.dns.pools = vec![UpstreamPool {
        name: "main".to_string(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["https://primary.example.com".to_string()],
        weight: None,
    }];

    let doc = save_and_reparse(&config, default_config_toml());
    let dns = doc.get("dns").unwrap().as_table().unwrap();

    let upstream = dns.get("upstream_servers").unwrap().as_array().unwrap();
    assert_eq!(upstream.len(), 1);
    assert_eq!(
        upstream.get(0).unwrap().as_str().unwrap(),
        "https://fallback.example.com"
    );
}

// ── Full config roundtrip ────────────────────────────────────────────────

#[test]
fn test_full_config_save_and_reload_preserves_pools() {
    let original = load_config(default_config_toml());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("roundtrip.toml");
    std::fs::write(&path, default_config_toml()).unwrap();

    save_config_to_file(&original, path.to_str().unwrap()).unwrap();

    let reloaded = Config::load(Some(path.to_str().unwrap()), Default::default()).unwrap();

    assert_eq!(reloaded.dns.pools.len(), original.dns.pools.len());
    for (orig, saved) in original.dns.pools.iter().zip(reloaded.dns.pools.iter()) {
        assert_eq!(orig.name, saved.name);
        assert_eq!(orig.strategy, saved.strategy);
        assert_eq!(orig.priority, saved.priority);
        assert_eq!(orig.servers, saved.servers);
    }
}

// ── Weight roundtrip ─────────────────────────────────────────────────────

#[test]
fn test_full_config_save_and_reload_preserves_weight() {
    let mut config = load_config(default_config_toml());
    config.dns.pools = vec![UpstreamPool {
        name: "weighted".to_string(),
        strategy: UpstreamStrategy::Balanced,
        priority: 1,
        servers: vec!["https://example.com".to_string()],
        weight: Some(10),
    }];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("weight_roundtrip.toml");
    std::fs::write(&path, default_config_toml()).unwrap();

    save_config_to_file(&config, path.to_str().unwrap()).unwrap();

    let reloaded = Config::load(Some(path.to_str().unwrap()), Default::default()).unwrap();

    assert_eq!(reloaded.dns.pools.len(), 1);
    assert_eq!(reloaded.dns.pools[0].weight, Some(10));
    assert_eq!(reloaded.dns.pools[0].strategy, UpstreamStrategy::Balanced);
}

// ── Inline comment preservation ──────────────────────────────────────────

#[test]
fn test_save_preserves_inline_comments() {
    let input_with_comments =
        default_config_toml().replace("dns_port = 53", "dns_port = 53  # UDP port for DNS");

    let config = load_config(&input_with_comments);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("comments.toml");
    std::fs::write(&path, &input_with_comments).unwrap();

    save_config_to_file(&config, path.to_str().unwrap()).unwrap();

    let output = std::fs::read_to_string(&path).unwrap();
    assert!(
        output.contains("# UDP port for DNS"),
        "inline comment should be preserved after save"
    );
}

// ── Error handling ───────────────────────────────────────────────────────

#[test]
fn test_save_config_to_nonexistent_path_returns_error() {
    let config = load_config(default_config_toml());
    let result = save_config_to_file(&config, "/nonexistent/path/config.toml");
    assert!(result.is_err());
}

#[test]
fn test_save_config_to_invalid_toml_returns_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.toml");
    std::fs::write(&path, "this is not valid [[[ toml").unwrap();

    let config = load_config(default_config_toml());
    let result = save_config_to_file(&config, path.to_str().unwrap());
    assert!(result.is_err());
}
