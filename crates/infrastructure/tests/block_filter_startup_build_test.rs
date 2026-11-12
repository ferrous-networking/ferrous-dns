//! The block filter's first build, the handle the listeners wait on before
//! they open, and the download that follows a start from kept copies
//! (issue #365).

#[path = "support/db.rs"]
mod db;
#[path = "support/list_host.rs"]
mod list_host;

use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlocklistSourceRepository, FilterDecision,
};
use ferrous_dns_infrastructure::dns::{BlockFilterEngine, ListCache, StartupBuild};
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use list_host::ListHost;
use sqlx::SqlitePool;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration};

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;
const LISTED: &str = "ads.startup.example";
const FRESH: &str = "fresh.startup.example";

async fn add_source(pool: &SqlitePool, url: String) {
    SqliteBlocklistSourceRepository::new(pool.clone())
        .create(
            "startup".to_owned(),
            Some(url),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
}

/// Starts an engine whose database would sit in `dir`, so its copies are kept
/// in `dir/lists`.
async fn start(pool: &SqlitePool, dir: &Path) -> (Arc<BlockFilterEngine>, StartupBuild) {
    let database = dir.join("ferrous.db");
    BlockFilterEngine::start(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
        ListCache::beside_database(database.to_str().unwrap()),
    )
    .await
    .unwrap()
}

fn is_blocked(engine: &BlockFilterEngine, domain: &str) -> bool {
    matches!(
        engine.check(domain, DEFAULT_GROUP_ID),
        FilterDecision::Block(_)
    )
}

async fn wait_until_blocked(engine: &BlockFilterEngine, domain: &str) {
    timeout(Duration::from_secs(10), async {
        while !is_blocked(engine, domain) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{domain} was never blocked"));
}

#[tokio::test]
async fn test_the_wait_ends_once_the_first_build_is_published() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    add_source(&pool, host.serve("/list.txt", &format!("{LISTED}\n"))).await;

    let (engine, startup) = start(&pool, dir.path()).await;

    assert!(startup.wait(Duration::from_secs(10)).await);
    assert!(
        is_blocked(&engine, LISTED),
        "the list is in force once the wait ends"
    );
}

#[tokio::test]
async fn test_the_wait_gives_up_at_its_limit_while_a_list_host_hangs() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    add_source(&pool, host.serve("/list.txt", &format!("{LISTED}\n"))).await;
    let release = host.hold_next();

    let (engine, startup) = start(&pool, dir.path()).await;

    assert!(
        !startup.wait(Duration::from_millis(200)).await,
        "the wait ends at its limit while the download hangs"
    );
    release.send(()).unwrap();
    wait_until_blocked(&engine, LISTED).await;
}

#[tokio::test]
async fn test_a_failed_first_build_still_ends_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    // The build reads this table after the lists; without it the build fails.
    sqlx::query("DROP TABLE regex_filters")
        .execute(&pool)
        .await
        .unwrap();

    let (_engine, startup) = start(&pool, dir.path()).await;

    assert!(startup.wait(Duration::from_secs(10)).await);
}

#[tokio::test]
async fn test_a_start_from_copies_downloads_the_lists_again_once_in_force() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    add_source(&pool, host.serve("/list.txt", &format!("{LISTED}\n"))).await;
    let (first_run, startup) = start(&pool, dir.path()).await;
    assert!(startup.wait(Duration::from_secs(10)).await);
    drop(first_run);

    host.serve("/list.txt", &format!("{FRESH}\n"));
    let release = host.hold_next();
    let (engine, startup) = start(&pool, dir.path()).await;
    assert!(
        startup.wait(Duration::from_secs(10)).await,
        "a start from copies needs no download"
    );
    assert!(
        is_blocked(&engine, LISTED),
        "the copy is in force before the download"
    );

    drop(release);
    wait_until_blocked(&engine, FRESH).await;
    assert!(
        !is_blocked(&engine, LISTED),
        "the download replaced the copy"
    );
    let copies: Vec<String> = fs::read_dir(dir.path().join("lists"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect();
    assert_eq!(
        copies,
        [format!("{FRESH}\n")],
        "the copy follows the download"
    );
}

#[tokio::test]
async fn test_a_start_without_copies_downloads_each_list_once() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::migrated_pool().await;
    let host = ListHost::spawn().await;
    add_source(&pool, host.serve("/list.txt", &format!("{LISTED}\n"))).await;

    let (_engine, startup) = start(&pool, dir.path()).await;
    assert!(startup.wait(Duration::from_secs(10)).await);
    // Room for a download that should not come.
    sleep(Duration::from_millis(500)).await;

    assert_eq!(
        host.downloads(),
        1,
        "a first start downloads once, not again"
    );
}
