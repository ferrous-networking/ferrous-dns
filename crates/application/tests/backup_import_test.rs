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
use ferrous_dns_application::use_cases::{CreateBlocklistSourceUseCase, ImportConfigUseCase};
use ferrous_dns_domain::{Config, DomainError, Group, LocalDnsRecord};
use serde_json::json;
use tokio::sync::RwLock;

mod helpers;
use helpers::{MockBlockFilterEngine, MockBlocklistSourceRepository, MockGroupRepository};

// ── Stubs for the ports this test does not exercise ──────────────────────────

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
    async fn create_local_record(
        &self,
        _hostname: String,
        _domain: Option<String>,
        _ip: String,
        _record_type: String,
        _ttl: Option<u32>,
    ) -> Result<LocalDnsRecord, DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
}

/// Swallows the write so an import never touches the filesystem.
struct NullConfigFilePersistence;

impl ConfigFilePersistence for NullConfigFilePersistence {
    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), String> {
        Ok(())
    }
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

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
    engine: Option<Arc<dyn BlockFilterEnginePort>>,
) -> (ImportConfigUseCase, Arc<MockBlocklistSourceRepository>) {
    let source_repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());

    let mut creator = CreateBlocklistSourceUseCase::new(source_repo.clone(), group_repo);
    if let Some(ref engine) = engine {
        creator = creator.with_block_filter(engine.clone());
    }
    let creator: Arc<dyn BlocklistSourceCreator> = Arc::new(creator);

    let mut import = ImportConfigUseCase::new(
        Arc::new(RwLock::new(Config::default())),
        Arc::new(NullConfigFilePersistence),
        Some("/tmp/ferrous-dns-backup-import-test.toml".to_string()),
        Arc::new(StubGroupCreator),
        creator,
        Arc::new(StubLocalRecordCreator),
    );
    if let Some(engine) = engine {
        import = import.with_block_filter(engine);
    }

    (import, source_repo)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_import_reloads_block_filter_once_for_the_whole_batch() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let (import, source_repo) = build_import(Some(engine.clone()));

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
    let (import, _source_repo) = build_import(Some(engine.clone()));

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
    let (import, source_repo) = build_import(Some(engine.clone()));

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
    assert_eq!(source_repo.count().await, 2);
    assert_eq!(
        engine.reload_count().await,
        2,
        "one rebuild per import call"
    );
}

#[tokio::test]
async fn test_import_succeeds_without_a_block_filter_engine() {
    let (import, source_repo) = build_import(None);

    let summary = import
        .execute(snapshot_with_sources(&["hagezi-pro", "oisd"]))
        .await
        .unwrap();

    assert_eq!(summary.blocklist_sources_imported, 2);
    assert_eq!(source_repo.count().await, 2);
}
