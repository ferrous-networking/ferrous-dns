use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

async fn create_test_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
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
        "CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            first_seen DATETIME,
            last_seen DATETIME,
            query_count INTEGER DEFAULT 0,
            last_mac_update DATETIME,
            last_hostname_update DATETIME,
            group_id INTEGER DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("PRAGMA foreign_keys = ON")
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
async fn test_create_and_get_group() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool);

    let group = repo
        .create("Test Group".to_string(), Some("Test comment".to_string()))
        .await
        .unwrap();

    assert_eq!(group.name.as_ref(), "Test Group");
    assert!(group.enabled);
    assert_eq!(
        group.comment.as_ref().map(|s| s.as_ref()),
        Some("Test comment")
    );
    assert!(!group.is_default);

    let fetched = repo.get_by_id(group.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Test Group");
}

#[tokio::test]
async fn test_get_by_name() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool);

    repo.create("Test Group".to_string(), None).await.unwrap();

    let fetched = repo.get_by_name("Test Group").await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Test Group");
}

#[tokio::test]
async fn test_get_all_groups() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool);

    repo.create("Group 1".to_string(), None).await.unwrap();
    repo.create("Group 2".to_string(), None).await.unwrap();

    let groups = repo.get_all().await.unwrap();
    assert!(groups.len() >= 3); 

    assert!(groups[0].is_default);
    assert_eq!(groups[0].name.as_ref(), "Protected");
}

#[tokio::test]
async fn test_update_group() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool);

    let group = repo.create("Original".to_string(), None).await.unwrap();
    let id = group.id.unwrap();

    let updated = repo
        .update(
            id,
            Some("Updated".to_string()),
            Some(false),
            Some("New comment".to_string()),
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Updated");
    assert!(!updated.enabled);
    assert_eq!(
        updated.comment.as_ref().map(|s| s.as_ref()),
        Some("New comment")
    );
}

#[tokio::test]
async fn test_delete_group() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool);

    let group = repo.create("To Delete".to_string(), None).await.unwrap();
    let id = group.id.unwrap();

    repo.delete(id).await.unwrap();

    let fetched = repo.get_by_id(id).await.unwrap();
    assert!(fetched.is_none());
}

#[tokio::test]
async fn test_unique_name_constraint() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool);

    repo.create("Unique Name".to_string(), None).await.unwrap();

    let result = repo.create("Unique Name".to_string(), None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_foreign_key_prevents_deletion() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool.clone());

    sqlx::query("INSERT INTO clients (ip_address, group_id) VALUES ('192.168.1.1', 1)")
        .execute(&pool)
        .await
        .unwrap();

    let result = repo.delete(1).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_count_clients_in_group() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool.clone());

    sqlx::query(
        "INSERT INTO clients (ip_address, group_id) VALUES ('192.168.1.1', 1), ('192.168.1.2', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let count = repo.count_clients_in_group(1).await.unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_get_clients_in_group() {
    let pool = create_test_db().await;
    let repo = SqliteGroupRepository::new(pool.clone());

    sqlx::query("INSERT INTO clients (ip_address, group_id) VALUES ('192.168.1.1', 1)")
        .execute(&pool)
        .await
        .unwrap();

    let clients = repo.get_clients_in_group(1).await.unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].ip_address.to_string(), "192.168.1.1");
}
