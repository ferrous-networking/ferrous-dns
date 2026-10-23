//! Guards how a backup import accounts for block index rebuilds.
//!
//! `ImportConfigUseCase` creates blocklist sources through the
//! `BlocklistSourceCreator` port, and that path deliberately does NOT reload the
//! block filter: a reload re-downloads every configured list, so restoring N
//! sources one reload at a time would cost N full downloads. The reload happens
//! exactly once, after the loop, and only when something was actually imported.
//!
//! The creator here is the real `CreateBlocklistSourceUseCase` wired to the same
//! engine as the import use case, so a regression that made the port path reload
//! per source would show up as an inflated count rather than passing silently.

use std::sync::Arc;

use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlocklistSourceCreator, ConfigFilePersistence, GroupCreator,
    LocalRecordCreator,
};
use ferrous_dns_application::use_cases::backup::snapshot::BackupSnapshot;
use ferrous_dns_application::use_cases::{
    ConfigDestination, CreateBlocklistSourceUseCase, ImportConfigUseCase,
};
use ferrous_dns_domain::{Config, DomainError, Group, LocalDnsRecord};
use serde_json::json;
use tokio::sync::RwLock;

mod helpers;
use helpers::{MockBlockFilterEngine, MockBlocklistSourceRepository, MockGroupRepository};

struct StubGroupCreator;

#[async_trait::async_trait]
impl GroupCreator for StubGroupCreator {
    async fn create_group(
        &self,
        _name: String,
        _comment: Option<String>,
    ) -> Result<Group, DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
}

struct StubLocalRecordCreator;

#[async_trait::async_trait]
impl LocalRecordCreator for StubLocalRecordCreator {
    async fn create_local_record(&self, _record: LocalDnsRecord) -> Result<(), DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
}

/// Swallows the write so an import never touches the filesystem.
struct NullConfigFilePersistence;

impl ConfigFilePersistence for NullConfigFilePersistence {
    fn load_config_from_file(&self, _path: &str) -> Result<Config, DomainError> {
        Ok(Config::default())
    }

    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Builds a version-1 snapshot carrying one blocklist source per name.
///
/// Groups and local records are left empty: this test is about the blocklist
/// reload accounting, and the stubs above would only add noise to the summary.
fn snapshot_with_sources(names: &[&str]) -> BackupSnapshot {
    let sources: Vec<_> = names
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "url": format!("https://example.com/{name}.txt"),
                "group_ids": [1],
                "comment": null,
                "enabled": true
            })
        })
        .collect();

    serde_json::from_value(json!({
        "version": "1",
        "ferrous_version": "0.0.0-test",
        "exported_at": "2026-01-01T00:00:00Z",
        "config": {
            "server": {
                "dns_port": 53,
                "web_port": 8080,
                "bind_address": "0.0.0.0",
                "pihole_compat": false,
                "tls_cert_path": "",
                "tls_key_path": "",
                "tls_enabled": false
            },
            "dns": {
                "upstream_servers": ["1.1.1.1:53"],
                "cache_enabled": true,
                "cache_eviction_strategy": "lru",
                "cache_max_entries": 1000,
                "cache_min_hit_rate": 0.0,
                "cache_min_frequency": 0,
                "cache_min_lfuk_score": 0.0,
                "cache_compaction_interval": 300,
                "cache_refresh_threshold": 0.8,
                "cache_optimistic_refresh": false,
                "cache_adaptive_thresholds": false,
                "cache_access_window_secs": 7200,
                "cache_min_ttl": 0,
                "cache_max_ttl": 86400,
                "block_non_fqdn": false,
                "block_private_ptr": false,
                "local_domain": null,
                "local_dns_server": null
            },
            "blocking": {
                "enabled": true,
                "custom_blocked": [],
                "whitelist": []
            },
            "logging": { "level": "info" },
            "auth": {
                "enabled": false,
                "session_ttl_hours": 24,
                "remember_me_days": 30,
                "login_rate_limit_attempts": 5,
                "login_rate_limit_window_secs": 300
            }
        },
        "data": {
            "groups": [],
            "blocklist_sources": sources,
            "local_records": []
        }
    }))
    .expect("snapshot fixture must deserialize")
}

/// Wires an import use case whose blocklist creator shares `engine`.
///
/// Sharing the engine is the point: if `CreateBlocklistSourceUseCase`'s port
/// path ever started reloading, the counts asserted below would grow by one per
/// imported source.
fn build_import(
    engine: Arc<dyn BlockFilterEnginePort>,
) -> (ImportConfigUseCase, Arc<MockBlocklistSourceRepository>) {
    let source_repo = Arc::new(MockBlocklistSourceRepository::new());
    let creator: Arc<dyn BlocklistSourceCreator> = Arc::new(CreateBlocklistSourceUseCase::new(
        source_repo.clone(),
        Arc::new(MockGroupRepository::new()),
        engine.clone(),
    ));

    let import = ImportConfigUseCase::new(
        ConfigDestination {
            config: Arc::new(RwLock::new(Config::default())),
            writer: Arc::default(),
            persistence: Arc::new(NullConfigFilePersistence),
            path: Some("/tmp/ferrous-dns-backup-import-test.toml".to_string()),
        },
        Arc::new(StubGroupCreator),
        Arc::new(MockGroupRepository::new()),
        creator,
        Arc::new(StubLocalRecordCreator),
        engine,
    );

    (import, source_repo)
}

#[tokio::test]
async fn test_import_reloads_block_filter_once_for_the_whole_batch() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let (import, source_repo) = build_import(engine.clone());

    let summary = import
        .execute(snapshot_with_sources(&[
            "hagezi-pro",
            "stevenblack",
            "oisd",
        ]))
        .await
        .unwrap();

    assert_eq!(
        summary.blocklist_sources_imported, 3,
        "all three sources must import, or the reload count below proves nothing"
    );
    assert_eq!(source_repo.count().await, 3);
    assert_eq!(
        engine.reload_count().await,
        1,
        "one rebuild for the batch; a per-source reload would re-download every list three times"
    );
}

#[tokio::test]
async fn test_import_without_blocklist_sources_does_not_reload() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let (import, _source_repo) = build_import(engine.clone());

    let summary = import.execute(snapshot_with_sources(&[])).await.unwrap();

    assert_eq!(summary.blocklist_sources_imported, 0);
    assert_eq!(
        engine.reload_count().await,
        0,
        "nothing was imported, so there is nothing to rebuild"
    );
}

#[tokio::test]
async fn test_import_reloads_once_when_some_sources_are_duplicates() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let (import, source_repo) = build_import(engine.clone());

    import
        .execute(snapshot_with_sources(&["hagezi-pro"]))
        .await
        .unwrap();

    // Re-importing the same source plus a new one: duplicates are skipped, but
    // the one real insert still earns exactly one rebuild.
    let summary = import
        .execute(snapshot_with_sources(&["hagezi-pro", "oisd"]))
        .await
        .unwrap();

    assert_eq!(summary.blocklist_sources_imported, 1);
    assert_eq!(summary.blocklist_sources_skipped, 1);
    assert!(
        summary.errors.is_empty(),
        "an existing source is skipped silently, not reported: {:?}",
        summary.errors
    );
    assert_eq!(source_repo.count().await, 2);
    assert_eq!(
        engine.reload_count().await,
        2,
        "one rebuild per import call"
    );
}

/// Holds the import mid-save until the test releases it.
struct GatedSave {
    started: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::Barrier>,
}

impl ConfigFilePersistence for GatedSave {
    fn load_config_from_file(&self, _path: &str) -> Result<Config, DomainError> {
        Ok(Config::default())
    }

    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), DomainError> {
        self.started.notify_one();
        self.release.wait();
        Ok(())
    }
}

fn import_with(
    config: Arc<RwLock<Config>>,
    config_writer: Arc<tokio::sync::Mutex<()>>,
    persistence: Arc<dyn ConfigFilePersistence>,
) -> ImportConfigUseCase {
    let engine: Arc<dyn BlockFilterEnginePort> = Arc::new(MockBlockFilterEngine::new());
    ImportConfigUseCase::new(
        ConfigDestination {
            config,
            writer: config_writer,
            persistence,
            path: Some("/tmp/ferrous-dns-backup-import-test.toml".to_string()),
        },
        Arc::new(StubGroupCreator),
        Arc::new(MockGroupRepository::new()),
        Arc::new(CreateBlocklistSourceUseCase::new(
            Arc::new(MockBlocklistSourceRepository::new()),
            Arc::new(MockGroupRepository::new()),
            engine.clone(),
        )),
        Arc::new(StubLocalRecordCreator),
        engine,
    )
}

/// Mirrors the API config-update test: a writer that does not take the config
/// writer lock (a local-record or password change) lands while the import is
/// saving, and must survive it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_does_not_overwrite_a_concurrent_config_write() {
    let config = Arc::new(RwLock::new(Config::default()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(std::sync::Barrier::new(2));
    let import = import_with(
        config.clone(),
        Arc::default(),
        Arc::new(GatedSave {
            started: started.clone(),
            release: release.clone(),
        }),
    );

    let save = tokio::spawn(async move { import.execute(snapshot_with_sources(&[])).await });
    started.notified().await;

    let writer_config = config.clone();
    let mut writer = tokio::spawn(async move {
        writer_config.write().await.dns.query_timeout = 7;
    });
    let writer_done = tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
        .await
        .is_ok();
    release.wait();

    let summary = save.await.unwrap().unwrap();
    assert!(summary.config_updated, "{:?}", summary.errors);
    if !writer_done {
        writer.await.unwrap();
    }

    let config = config.read().await;
    assert_eq!(config.dns.query_timeout, 7, "the concurrent write was lost");
    assert_eq!(
        config.dns.cache_max_entries, 1000,
        "the import was not applied"
    );
}

#[tokio::test]
async fn test_import_waits_for_the_config_writer() {
    let config = Arc::new(RwLock::new(Config::default()));
    let config_writer: Arc<tokio::sync::Mutex<()>> = Arc::default();
    let import = import_with(
        config.clone(),
        config_writer.clone(),
        Arc::new(NullConfigFilePersistence),
    );

    let save_in_flight = config_writer.lock().await;
    let mut run = tokio::spawn(async move { import.execute(snapshot_with_sources(&[])).await });
    let finished_early = tokio::time::timeout(std::time::Duration::from_millis(100), &mut run)
        .await
        .is_ok();
    assert!(
        !finished_early,
        "an import must not interleave with a config save"
    );
    assert_ne!(config.read().await.dns.cache_max_entries, 1000);
    drop(save_in_flight);

    assert!(run.await.unwrap().unwrap().config_updated);
    assert_eq!(config.read().await.dns.cache_max_entries, 1000);
}
