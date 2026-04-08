use ferrous_dns_application::ports::ConfigRepository;
use ferrous_dns_domain::{Config, LocalDnsRecord};
use ferrous_dns_infrastructure::repositories::TomlConfigRepository;

fn minimal_toml() -> &'static str {
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
dnssec_enabled = false
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
block_non_fqdn = false

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

fn config_with_records(records: Vec<LocalDnsRecord>) -> Config {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.toml");
    std::fs::write(&path, minimal_toml()).unwrap();
    let mut config = Config::load(Some(path.to_str().unwrap()), Default::default()).unwrap();
    config.dns.local_records = records;
    config
}

// ── TomlConfigRepository: save_local_records ────────────────────────────────

#[tokio::test]
async fn test_save_local_records_writes_to_correct_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrous-dns.toml");
    std::fs::write(&path, minimal_toml()).unwrap();

    let config = config_with_records(vec![LocalDnsRecord {
        hostname: "myserver".to_string(),
        domain: Some("lan".to_string()),
        ip: "10.0.0.10".to_string(),
        record_type: "A".to_string(),
        ttl: Some(300),
    }]);

    let repo = TomlConfigRepository::new(path.to_str().unwrap().to_string());
    repo.save_local_records(&config).await.unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("myserver"));
    assert!(content.contains("10.0.0.10"));
    assert!(content.contains("lan"));
}

#[tokio::test]
async fn test_save_local_records_roundtrips_multiple_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrous-dns.toml");
    std::fs::write(&path, minimal_toml()).unwrap();

    let config = config_with_records(vec![
        LocalDnsRecord {
            hostname: "host1".to_string(),
            domain: Some("local".to_string()),
            ip: "192.168.1.10".to_string(),
            record_type: "A".to_string(),
            ttl: Some(60),
        },
        LocalDnsRecord {
            hostname: "host2".to_string(),
            domain: None,
            ip: "192.168.1.20".to_string(),
            record_type: "A".to_string(),
            ttl: None,
        },
    ]);

    let repo = TomlConfigRepository::new(path.to_str().unwrap().to_string());
    repo.save_local_records(&config).await.unwrap();

    let reloaded = Config::load(Some(path.to_str().unwrap()), Default::default()).unwrap();
    assert_eq!(reloaded.dns.local_records.len(), 2);
    assert_eq!(reloaded.dns.local_records[0].hostname, "host1");
    assert_eq!(reloaded.dns.local_records[0].ip, "192.168.1.10");
    assert_eq!(reloaded.dns.local_records[1].hostname, "host2");
    assert_eq!(reloaded.dns.local_records[1].ip, "192.168.1.20");
    assert!(reloaded.dns.local_records[1].domain.is_none());
}

#[tokio::test]
async fn test_save_local_records_clears_records_when_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrous-dns.toml");

    let toml_with_record = format!(
        "{}\n[[dns.local_records]]\nhostname = \"old\"\nip = \"1.2.3.4\"\nrecord_type = \"A\"\n",
        minimal_toml()
    );
    std::fs::write(&path, &toml_with_record).unwrap();

    let config = config_with_records(vec![]);

    let repo = TomlConfigRepository::new(path.to_str().unwrap().to_string());
    repo.save_local_records(&config).await.unwrap();

    let reloaded = Config::load(Some(path.to_str().unwrap()), Default::default()).unwrap();
    assert!(reloaded.dns.local_records.is_empty());
}

#[tokio::test]
async fn test_save_local_records_returns_error_for_nonexistent_path() {
    let config = config_with_records(vec![]);
    let repo = TomlConfigRepository::new("/nonexistent/path/ferrous-dns.toml".to_string());
    let result = repo.save_local_records(&config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_toml_repository_uses_injected_path_not_cwd() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let path_a = dir_a.path().join("config-a.toml");
    let path_b = dir_b.path().join("config-b.toml");

    std::fs::write(&path_a, minimal_toml()).unwrap();
    std::fs::write(&path_b, minimal_toml()).unwrap();

    let config = config_with_records(vec![LocalDnsRecord {
        hostname: "unique-host".to_string(),
        domain: Some("test".to_string()),
        ip: "10.99.99.99".to_string(),
        record_type: "A".to_string(),
        ttl: Some(120),
    }]);

    let repo = TomlConfigRepository::new(path_a.to_str().unwrap().to_string());
    repo.save_local_records(&config).await.unwrap();

    let content_a = std::fs::read_to_string(&path_a).unwrap();
    let content_b = std::fs::read_to_string(&path_b).unwrap();

    assert!(content_a.contains("unique-host"), "path_a must be updated");
    assert!(
        !content_b.contains("unique-host"),
        "path_b must NOT be touched"
    );
}
