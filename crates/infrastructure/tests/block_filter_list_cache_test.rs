//! The copies of downloaded lists kept beside the database, which a start
//! compiles from before it downloads anything (issue #365).

#[path = "support/db.rs"]
mod db;
#[path = "support/list_host.rs"]
mod list_host;

use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlocklistSourceRepository, FilterDecision, WhitelistSourceRepository,
};
use ferrous_dns_infrastructure::dns::{BlockFilterEngine, ListCache, StartupBuild};
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use list_host::ListHost;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;
const LISTED: &str = "ads.startup.example";
/// On the blocklist and on the allowlist, so only the allowlist lets it through.
const ALLOWED: &str = "allowed.startup.example";

async fn add_blocklist(pool: &SqlitePool, url: String) -> i64 {
    SqliteBlocklistSourceRepository::new(pool.clone())
        .create(
            format!("block {url}"),
            Some(url),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap()
        .id
        .unwrap()
}

async fn add_allowlist(pool: &SqlitePool, url: String) {
    SqliteWhitelistSourceRepository::new(pool.clone())
        .create(
            format!("allow {url}"),
            Some(url),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
}

/// Starts an engine whose database would sit in `dir`, and waits for its
/// first build.
async fn start(pool: &SqlitePool, dir: &Path) -> Arc<BlockFilterEngine> {
    let database = dir.join("ferrous.db");
    let (engine, startup): (_, StartupBuild) = BlockFilterEngine::start(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
        ListCache::beside_database(database.to_str().unwrap()),
    )
    .await
    .unwrap();
    assert!(startup.wait(Duration::from_secs(10)).await);
    engine
}

fn is_blocked(engine: &BlockFilterEngine, domain: &str) -> bool {
    matches!(
        engine.check(domain, DEFAULT_GROUP_ID),
        FilterDecision::Block(_)
    )
}

/// Where the copy of `url` is kept.
fn copy_path(dir: &Path, url: &str) -> PathBuf {
    let hash: String = Sha256::digest(url.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    dir.join("lists").join(format!("{hash}.txt"))
}

#[tokio::test]
async fn test_a_download_is_kept_under_the_hash_of_its_url() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    let url = host.serve("/list.txt?token=secret", &format!("{LISTED}\n"));
    add_blocklist(&pool, url.clone()).await;

    start(&pool, dir.path()).await;

    assert_eq!(
        fs::read_to_string(copy_path(dir.path(), &url)).unwrap(),
        format!("{LISTED}\n")
    );
}

#[tokio::test]
async fn test_a_restart_compiles_block_and_allow_lists_from_their_copies() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    add_blocklist(
        &pool,
        host.serve("/block.txt", &format!("{LISTED}\n{ALLOWED}\n")),
    )
    .await;
    add_allowlist(&pool, host.serve("/allow.txt", &format!("{ALLOWED}\n"))).await;
    drop(start(&pool, dir.path()).await);

    host.fail();
    let engine = start(&pool, dir.path()).await;

    assert!(
        is_blocked(&engine, LISTED),
        "the blocklist copy is in force"
    );
    assert!(
        !is_blocked(&engine, ALLOWED),
        "the allowlist copy is in force"
    );
}

#[tokio::test]
async fn test_a_removed_source_loses_its_copy_and_other_files_stay() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    let removed = host.serve("/removed.txt", "removed.startup.example\n");
    let kept = host.serve("/kept.txt", &format!("{LISTED}\n"));
    let removed_id = add_blocklist(&pool, removed.clone()).await;
    add_blocklist(&pool, kept.clone()).await;
    let engine = start(&pool, dir.path()).await;
    let notes = dir.path().join("lists").join("notes.txt");
    fs::write(&notes, "not a copy").unwrap();
    assert!(copy_path(dir.path(), &removed).exists());

    SqliteBlocklistSourceRepository::new(pool.clone())
        .delete(removed_id)
        .await
        .unwrap();
    engine.reload().await.unwrap();

    assert!(!copy_path(dir.path(), &removed).exists());
    assert!(copy_path(dir.path(), &kept).exists());
    assert!(notes.exists(), "a file the cache did not write stays");
}

#[tokio::test]
async fn test_lists_are_published_when_no_copy_can_be_kept() {
    let dir = tempfile::tempdir().unwrap();
    // A file where the directory would go.
    fs::write(dir.path().join("lists"), "").unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    add_blocklist(&pool, host.serve("/list.txt", &format!("{LISTED}\n"))).await;

    let engine = start(&pool, dir.path()).await;

    assert!(is_blocked(&engine, LISTED));
}

#[tokio::test]
async fn test_a_reload_reuses_a_held_list_without_reading_its_copy() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    let url = host.serve("/list.txt", &format!("{LISTED}\n"));
    add_blocklist(&pool, url.clone()).await;
    let engine = start(&pool, dir.path()).await;

    fs::write(copy_path(dir.path(), &url), "other.startup.example\n").unwrap();
    engine.reload().await.unwrap();

    assert!(is_blocked(&engine, LISTED));
    assert!(!is_blocked(&engine, "other.startup.example"));
}
