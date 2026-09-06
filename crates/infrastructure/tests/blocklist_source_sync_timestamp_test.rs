//! Tests for the `last_synced_at` column on `blocklist_sources` and
//! `whitelist_sources`.
//!
//! The column exists so a source that stops fetching becomes visible: only a
//! successful download stamps it, so a date that stops advancing is the signal
//! that a URL has gone dead. A 404 is otherwise only `warn!`-logged while the
//! reload still reports success, which is how the broken HaGeZi URLs in issue
//! #216 stayed invisible.
//!
//! The write itself goes through `mark_sources_synced` rather than the
//! repositories, because the compiler stamps sources from the fetch path where
//! it already holds the pool and the source ids.

use ferrous_dns_application::ports::{BlocklistSourceRepository, WhitelistSourceRepository};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::block_filter::mark_sources_synced;
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use sqlx::SqlitePool;

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;

/// RFC 3339 UTC, the shape the compiler writes so JavaScript's `new Date()`
/// does not read the value as local time.
const STAMP: &str = "2026-09-06T18:25:19+00:00";

/// A fresh migrated database. The returned `TempDir` must outlive the pool.
async fn test_pool() -> (SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    (pool, dir)
}

#[tokio::test]
async fn test_last_synced_at_is_null_on_a_new_source() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create(
            "Never Fetched".to_string(),
            Some("https://example.test/list.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();

    assert!(
        source.last_synced_at.is_none(),
        "a source that has never been fetched must report no sync date"
    );

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert!(
        fetched.last_synced_at.is_none(),
        "the null must survive a round trip through the database"
    );
}

#[tokio::test]
async fn test_mark_sources_synced_stamps_only_the_given_ids() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    let working = repo
        .create(
            "Working".to_string(),
            Some("https://example.test/good.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
    let broken = repo
        .create(
            "Broken".to_string(),
            Some("https://example.test/404.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();

    // Only the source that actually downloaded is passed in — this is the 404
    // case from the issue, where one list syncs and its neighbour does not.
    mark_sources_synced(&pool, "blocklist_sources", &[working.id.unwrap()], STAMP)
        .await
        .unwrap();

    let working = repo.get_by_id(working.id.unwrap()).await.unwrap().unwrap();
    let broken = repo.get_by_id(broken.id.unwrap()).await.unwrap().unwrap();

    assert_eq!(
        working.last_synced_at.as_deref(),
        Some(STAMP),
        "a source that fetched successfully must carry the stamp"
    );
    assert!(
        broken.last_synced_at.is_none(),
        "a source that failed to fetch must stay blank, which is what makes a dead URL visible"
    );
}

#[tokio::test]
async fn test_mark_sources_synced_with_no_ids_is_a_no_op() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    let source = repo
        .create(
            "Untouched".to_string(),
            Some("https://example.test/list.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();

    // A reload where every source failed passes an empty slice; building an
    // `IN ()` statement for it would be a syntax error.
    mark_sources_synced(&pool, "blocklist_sources", &[], STAMP)
        .await
        .expect("an empty id slice must not error");

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert!(
        fetched.last_synced_at.is_none(),
        "no ids means no rows touched"
    );
}

#[tokio::test]
async fn test_mark_sources_synced_stamps_whitelist_sources() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteWhitelistSourceRepository::new(pool.clone());

    let source = repo
        .create(
            "Allowlist".to_string(),
            Some("https://example.test/allow.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();

    mark_sources_synced(&pool, "whitelist_sources", &[source.id.unwrap()], STAMP)
        .await
        .unwrap();

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(
        fetched.last_synced_at.as_deref(),
        Some(STAMP),
        "allowlist sources are fetched over HTTP too and get the same treatment"
    );
}

#[tokio::test]
async fn test_update_preserves_last_synced_at() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    let source = repo
        .create(
            "Original Name".to_string(),
            Some("https://example.test/list.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
    let id = source.id.unwrap();

    mark_sources_synced(&pool, "blocklist_sources", &[id], STAMP)
        .await
        .unwrap();

    // `update`'s SET clause deliberately omits `last_synced_at`: renaming a
    // source or moving it between groups says nothing about when it last
    // downloaded, and clearing the stamp would make a healthy source look as
    // though it had never synced.
    let updated = repo
        .update(
            id,
            Some("Renamed".to_string()),
            None,
            None,
            Some("now with a comment".to_string()),
            Some(false),
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Renamed");
    assert_eq!(
        updated.last_synced_at.as_deref(),
        Some(STAMP),
        "an unrelated update must not clear the sync date"
    );

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(
        fetched.last_synced_at.as_deref(),
        Some(STAMP),
        "the preserved stamp must be what is actually stored, not just what update returned"
    );
}
