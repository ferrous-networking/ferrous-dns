use ferrous_dns_application::ports::ClientSubnetRepository;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::SqliteClientSubnetRepository;
use sqlx::sqlite::SqlitePoolOptions;

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            comment TEXT,
            is_default BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO groups (id, name) VALUES (1, 'Office'), (2, 'Guest')")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE client_subnets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet_cidr TEXT NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

#[tokio::test]
async fn test_create_subnet_success() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let result = repo
        .create(
            "192.168.1.0/24".to_string(),
            1,
            Some("Office network".to_string()),
        )
        .await;

    assert!(result.is_ok());
    let created = result.unwrap();
    assert!(created.id.is_some());
    assert_eq!(created.subnet_cidr.to_string(), "192.168.1.0/24");
    assert_eq!(created.group_id, 1);
    assert_eq!(
        created.comment.as_ref().map(|s| s.as_ref()),
        Some("Office network")
    );
    assert!(created.created_at.is_some());
}

#[tokio::test]
async fn test_create_subnet_duplicate() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    repo.create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();

    let result = repo.create("192.168.1.0/24".to_string(), 2, None).await;

    assert!(result.is_err());
    matches!(result.unwrap_err(), DomainError::SubnetConflict(_));
}

#[tokio::test]
async fn test_create_subnet_invalid_group() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let result = repo.create("192.168.1.0/24".to_string(), 999, None).await;

    assert!(result.is_err());
    matches!(result.unwrap_err(), DomainError::GroupNotFound(_));
}

#[tokio::test]
async fn test_get_all_subnets_empty() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let result = repo.get_all().await;

    assert!(result.is_ok());
    let subnets = result.unwrap();
    assert_eq!(subnets.len(), 0);
}

#[tokio::test]
async fn test_get_all_subnets_multiple() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    repo.create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();
    repo.create("10.0.0.0/8".to_string(), 2, None)
        .await
        .unwrap();
    repo.create("172.16.0.0/12".to_string(), 1, None)
        .await
        .unwrap();

    let result = repo.get_all().await;

    assert!(result.is_ok());
    let subnets = result.unwrap();
    assert_eq!(subnets.len(), 3);
}

#[tokio::test]
async fn test_get_by_id_success() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let created = repo
        .create("192.168.1.0/24".to_string(), 1, Some("Test".to_string()))
        .await
        .unwrap();
    let id = created.id.unwrap();

    let result = repo.get_by_id(id).await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.is_some());
    let subnet = found.unwrap();
    assert_eq!(subnet.id, Some(id));
    assert_eq!(subnet.subnet_cidr.to_string(), "192.168.1.0/24");
    assert_eq!(subnet.comment.as_ref().map(|s| s.as_ref()), Some("Test"));
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let result = repo.get_by_id(999).await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_delete_subnet_success() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let created = repo
        .create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();
    let id = created.id.unwrap();

    let result = repo.delete(id).await;
    assert!(result.is_ok());

    let found = repo.get_by_id(id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_delete_subnet_not_found() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let result = repo.delete(999).await;

    assert!(result.is_err());
    matches!(result.unwrap_err(), DomainError::SubnetNotFound(_));
}

#[tokio::test]
async fn test_exists_true() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    repo.create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();

    let result = repo.exists("192.168.1.0/24").await;

    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_exists_false() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let result = repo.exists("192.168.1.0/24").await;

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_repository_with_various_cidrs() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool);

    let subnets = vec![
        ("192.168.1.0/24", 1),
        ("10.0.0.0/8", 2),
        ("172.16.0.0/12", 1),
        ("2001:db8::/32", 2),
    ];

    for (cidr, group_id) in subnets {
        let result = repo.create(cidr.to_string(), group_id, None).await;
        assert!(result.is_ok(), "Failed to create subnet {}", cidr);
    }

    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 4);
}

#[tokio::test]
async fn test_delete_cascades_on_group_deletion() {
    let pool = create_test_db().await;
    let repo = SqliteClientSubnetRepository::new(pool.clone());

    repo.create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();

    sqlx::query("DELETE FROM groups WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();

    let subnets = repo.get_all().await.unwrap();
    assert_eq!(subnets.len(), 0);
}
