//! Shared source SQL is covered in blocklist_source_repository_tests.rs; these prove the whitelist wiring.

use ferrous_dns_application::ports::WhitelistSourceRepository;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use sqlx::{AssertSqlSafe, SqlitePool};

#[path = "support/db.rs"]
mod db;

async fn count(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn crud_round_trip_uses_whitelist_tables() {
    let pool = db::migrated_pool().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (2, 'Office')")
        .execute(&pool)
        .await
        .unwrap();
    let repo = SqliteWhitelistSourceRepository::new(pool.clone());

    let created = repo
        .create(
            "Allow List".to_string(),
            Some("https://example.com/allow.txt".to_string()),
            vec![2, 1],
            Some("note".to_string()),
            true,
        )
        .await
        .unwrap();
    let id = created.id.unwrap();
    assert_eq!(created.group_ids, vec![1, 2]);
    assert_eq!(count(&pool, "whitelist_sources").await, 1);
    assert_eq!(count(&pool, "whitelist_source_groups").await, 2);
    assert_eq!(count(&pool, "blocklist_sources").await, 0);
    assert_eq!(count(&pool, "blocklist_source_groups").await, 0);

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Allow List");
    assert_eq!(
        fetched.url.as_deref(),
        Some("https://example.com/allow.txt")
    );
    assert_eq!(fetched.group_ids, vec![1, 2]);

    let updated = repo
        .update(id, None, Some(None), Some(vec![2]), None, Some(false))
        .await
        .unwrap();
    assert!(updated.url.is_none());
    assert_eq!(updated.group_ids, vec![2]);
    assert!(!updated.enabled);
    assert_eq!(updated.comment.as_deref(), Some("note"));

    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].group_ids, vec![2]);

    repo.delete(id).await.unwrap();
    assert!(repo.get_by_id(id).await.unwrap().is_none());
    assert_eq!(count(&pool, "whitelist_source_groups").await, 0);
}

#[tokio::test]
async fn duplicate_name_is_invalid_whitelist_source() {
    let pool = db::migrated_pool().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    repo.create("Dup".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let result = repo
        .create("Dup".to_string(), None, vec![1], None, true)
        .await;
    assert!(
        matches!(result, Err(DomainError::AlreadyExists(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn missing_source_is_whitelist_source_not_found() {
    let pool = db::migrated_pool().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    assert!(matches!(
        repo.update(999, None, None, None, None, Some(false)).await,
        Err(DomainError::WhitelistSourceNotFound(999))
    ));
    assert!(matches!(
        repo.delete(999).await,
        Err(DomainError::WhitelistSourceNotFound(999))
    ));
}
