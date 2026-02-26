use ferrous_dns_application::ports::ManagedDomainRepository;
use ferrous_dns_domain::DomainAction;
use ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository;
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
        "CREATE TABLE IF NOT EXISTS managed_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
            comment TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            service_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
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
async fn test_create_and_get_by_id() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let domain = repo
        .create(
            "Block Ads".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            Some("Block ads".to_string()),
            true,
        )
        .await
        .unwrap();

    assert!(domain.id.is_some());
    assert_eq!(domain.name.as_ref(), "Block Ads");
    assert_eq!(domain.domain.as_ref(), "ads.example.com");
    assert_eq!(domain.action, DomainAction::Deny);
    assert_eq!(domain.group_id, 1);
    assert_eq!(domain.comment.as_deref(), Some("Block ads"));
    assert!(domain.enabled);
    assert!(domain.created_at.is_some());
    assert!(domain.updated_at.is_some());

    let id = domain.id.unwrap();
    let fetched = repo.get_by_id(id).await.unwrap();
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.name.as_ref(), "Block Ads");
    assert_eq!(fetched.action, DomainAction::Deny);
}

#[tokio::test]
async fn test_create_allow_action() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let domain = repo
        .create(
            "Allow Company".to_string(),
            "mycompany.com".to_string(),
            DomainAction::Allow,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    assert_eq!(domain.action, DomainAction::Allow);
    assert!(domain.comment.is_none());
}

#[tokio::test]
async fn test_create_duplicate_name_fails() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    repo.create(
        "Duplicate".to_string(),
        "ads.example.com".to_string(),
        DomainAction::Deny,
        1,
        None,
        true,
    )
    .await
    .unwrap();

    let result = repo
        .create(
            "Duplicate".to_string(),
            "tracker.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ferrous_dns_domain::DomainError::InvalidManagedDomain(_) => {}
        other => panic!("Expected InvalidManagedDomain, got {:?}", other),
    }
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let result = repo.get_by_id(999).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_all_empty() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let result = repo.get_all().await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_get_all_ordered_by_name() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    repo.create(
        "Zebra Domain".to_string(),
        "zebra.com".to_string(),
        DomainAction::Deny,
        1,
        None,
        true,
    )
    .await
    .unwrap();
    repo.create(
        "Alpha Domain".to_string(),
        "alpha.com".to_string(),
        DomainAction::Allow,
        1,
        None,
        true,
    )
    .await
    .unwrap();
    repo.create(
        "Middle Domain".to_string(),
        "middle.com".to_string(),
        DomainAction::Deny,
        1,
        None,
        false,
    )
    .await
    .unwrap();

    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].name.as_ref(), "Alpha Domain");
    assert_eq!(all[1].name.as_ref(), "Middle Domain");
    assert_eq!(all[2].name.as_ref(), "Zebra Domain");
}

#[tokio::test]
async fn test_update_name() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let created = repo
        .create(
            "Original Name".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let id = created.id.unwrap();
    let updated = repo
        .update(
            id,
            Some("New Name".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "New Name");
    assert_eq!(updated.domain.as_ref(), "ads.example.com");
}

#[tokio::test]
async fn test_update_action() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let created = repo
        .create(
            "Action Test".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let id = created.id.unwrap();
    let updated = repo
        .update(id, None, None, Some(DomainAction::Allow), None, None, None)
        .await
        .unwrap();

    assert_eq!(updated.action, DomainAction::Allow);
}

#[tokio::test]
async fn test_update_enabled_toggle() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let created = repo
        .create(
            "Toggle Test".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let id = created.id.unwrap();
    let updated = repo
        .update(id, None, None, None, None, None, Some(false))
        .await
        .unwrap();

    assert!(!updated.enabled);
}

#[tokio::test]
async fn test_update_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let result = repo
        .update(
            999,
            Some("New Name".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ferrous_dns_domain::DomainError::ManagedDomainNotFound(_) => {}
        other => panic!("Expected ManagedDomainNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_delete_success() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let created = repo
        .create(
            "To Delete".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let id = created.id.unwrap();
    assert_eq!(repo.get_all().await.unwrap().len(), 1);

    repo.delete(id).await.unwrap();
    assert_eq!(repo.get_all().await.unwrap().len(), 0);
    assert!(repo.get_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteManagedDomainRepository::new(pool);

    let result = repo.delete(999).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ferrous_dns_domain::DomainError::ManagedDomainNotFound(_) => {}
        other => panic!("Expected ManagedDomainNotFound, got {:?}", other),
    }
}
