use ferrous_dns_application::ports::WhitelistSourceRepository;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

async fn create_test_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            comment TEXT,
            is_default BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS whitelist_sources (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            url        TEXT,
            group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
            comment    TEXT,
            enabled    BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO groups (id, name, enabled, comment, is_default)
         VALUES (1, 'Protected', 1, 'Default group', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

#[tokio::test]
async fn test_create_and_get_source() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let source = repo
        .create(
            "AdGuard Allowlist".to_string(),
            Some("https://adguard.com/allowlist.txt".to_string()),
            1,
            Some("Allow list for trusted domains".to_string()),
            true,
        )
        .await
        .unwrap();

    assert!(source.id.is_some());
    assert_eq!(source.name.as_ref(), "AdGuard Allowlist");
    assert_eq!(
        source.url.as_deref(),
        Some("https://adguard.com/allowlist.txt")
    );
    assert_eq!(source.group_id, 1);
    assert_eq!(
        source.comment.as_deref(),
        Some("Allow list for trusted domains")
    );
    assert!(source.enabled);
    assert!(source.created_at.is_some());
    assert!(source.updated_at.is_some());

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "AdGuard Allowlist");
}

#[tokio::test]
async fn test_create_without_url() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let source = repo
        .create("Manual Allowlist".to_string(), None, 1, None, true)
        .await
        .unwrap();

    assert!(source.url.is_none());
    assert!(source.comment.is_none());
}

#[tokio::test]
async fn test_create_unique_name_constraint() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    repo.create("Duplicate Name".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let result = repo
        .create("Duplicate Name".to_string(), None, 1, None, false)
        .await;

    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("already exists") || err_str.contains("InvalidWhitelistSource"),
        "Expected duplicate name error, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_get_all_empty() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let sources = repo.get_all().await.unwrap();
    assert_eq!(sources.len(), 0);
}

#[tokio::test]
async fn test_get_all_ordered_by_name() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    repo.create("Zzz Allowlist".to_string(), None, 1, None, true)
        .await
        .unwrap();
    repo.create("Aaa Allowlist".to_string(), None, 1, None, true)
        .await
        .unwrap();
    repo.create("Mmm Allowlist".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let sources = repo.get_all().await.unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[0].name.as_ref(), "Aaa Allowlist");
    assert_eq!(sources[1].name.as_ref(), "Mmm Allowlist");
    assert_eq!(sources[2].name.as_ref(), "Zzz Allowlist");
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let result = repo.get_by_id(999).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_enabled_field() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let source = repo
        .create("Toggle Allowlist".to_string(), None, 1, None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let updated = repo
        .update(id, None, None, None, None, Some(false))
        .await
        .unwrap();

    assert!(!updated.enabled);

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert!(!fetched.enabled);
}

#[tokio::test]
async fn test_update_name() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let source = repo
        .create("Old Name".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let updated = repo
        .update(
            source.id.unwrap(),
            Some("New Name".to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "New Name");
}

#[tokio::test]
async fn test_update_group_id() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool.clone());

    sqlx::query("INSERT INTO groups (id, name) VALUES (2, 'Office')")
        .execute(&pool)
        .await
        .unwrap();

    let source = repo
        .create("Group Test".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let updated = repo
        .update(source.id.unwrap(), None, None, Some(2), None, None)
        .await
        .unwrap();

    assert_eq!(updated.group_id, 2);
}

#[tokio::test]
async fn test_update_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let result = repo.update(999, None, None, None, None, Some(false)).await;

    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("WhitelistSourceNotFound") || err_str.contains("not found"),
        "Expected not found error, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_update_clear_url() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let source = repo
        .create(
            "URL Allowlist".to_string(),
            Some("https://example.com/allow.txt".to_string()),
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let updated = repo
        .update(source.id.unwrap(), None, Some(None), None, None, None)
        .await
        .unwrap();

    assert!(updated.url.is_none());
}

#[tokio::test]
async fn test_delete_success() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let source = repo
        .create("To Delete".to_string(), None, 1, None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    repo.delete(id).await.unwrap();

    let fetched = repo.get_by_id(id).await.unwrap();
    assert!(fetched.is_none());
}

#[tokio::test]
async fn test_delete_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool);

    let result = repo.delete(999).await;
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("WhitelistSourceNotFound") || err_str.contains("not found"),
        "Expected not found error, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_fk_group_restricts_delete() {
    let pool = create_test_db().await;
    let repo = SqliteWhitelistSourceRepository::new(pool.clone());

    repo.create("FK Test Allowlist".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let result = sqlx::query("DELETE FROM groups WHERE id = 1")
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "FK constraint should prevent group deletion"
    );
}
