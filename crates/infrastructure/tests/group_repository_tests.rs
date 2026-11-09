#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository;
use sqlx::SqlitePool;

async fn repo() -> (SqliteGroupRepository, SqlitePool) {
    let pool = db::migrated_pool().await;
    (SqliteGroupRepository::new(pool.clone()), pool)
}

async fn insert_client(pool: &SqlitePool, ip: &str, group_id: i64) {
    sqlx::query("INSERT INTO clients (ip_address, group_id) VALUES (?, ?)")
        .bind(ip)
        .bind(group_id)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_and_get_group() {
    let (repo, _pool) = repo().await;

    let group = repo
        .create(
            "Test Group".to_string(),
            Some("Test comment".to_string()),
            true,
            true,
        )
        .await
        .unwrap();

    assert_eq!(group.name.as_ref(), "Test Group");
    assert!(group.enabled);
    assert_eq!(group.comment.as_deref(), Some("Test comment"));
    assert!(!group.is_default);
    assert!(group.malware_detection_enabled);

    let fetched = repo.get_by_id(group.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Test Group");
}

#[tokio::test]
async fn test_get_by_name() {
    let (repo, _pool) = repo().await;
    repo.create("Test Group".to_string(), None, true, true)
        .await
        .unwrap();

    let fetched = repo.get_by_name("Test Group").await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Test Group");
    assert!(repo.get_by_name("Missing").await.unwrap().is_none());
}

/// Groups that existed before the column, and rows written without it, keep
/// the malware detectors on.
#[tokio::test]
async fn test_groups_written_without_the_flag_keep_malware_detection_on() {
    let (repo, pool) = repo().await;
    sqlx::query("INSERT INTO groups (name) VALUES ('Legacy')")
        .execute(&pool)
        .await
        .unwrap();

    let groups = repo.get_all().await.unwrap();

    assert_eq!(groups.len(), 2);
    assert!(
        groups.iter().all(|g| g.malware_detection_enabled),
        "{groups:?}"
    );
}

#[tokio::test]
async fn test_get_all_lists_default_group_first() {
    let (repo, _pool) = repo().await;
    repo.create("Alpha".to_string(), None, true, true)
        .await
        .unwrap();
    repo.create("Beta".to_string(), None, true, true)
        .await
        .unwrap();

    let groups = repo.get_all().await.unwrap();

    let names: Vec<&str> = groups.iter().map(|g| g.name.as_ref()).collect();
    assert_eq!(names, vec!["Protected", "Alpha", "Beta"]);
    assert!(groups[0].is_default);
    assert!(groups[0].enabled);
}

#[tokio::test]
async fn test_get_all_with_client_counts() {
    let (repo, pool) = repo().await;
    let kids = repo
        .create("Kids".to_string(), None, true, true)
        .await
        .unwrap();
    let kids_id = kids.id.unwrap();
    insert_client(&pool, "192.168.1.1", kids_id).await;
    insert_client(&pool, "192.168.1.2", kids_id).await;

    let counts = repo.get_all_with_client_counts().await.unwrap();

    let summary: Vec<(&str, bool, u64)> = counts
        .iter()
        .map(|(g, n)| (g.name.as_ref(), g.is_default, *n))
        .collect();
    assert_eq!(summary, vec![("Protected", true, 0), ("Kids", false, 2)]);
}

#[tokio::test]
async fn test_update_group() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create("Original".to_string(), None, true, true)
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(
            id,
            Some("Updated".to_string()),
            Some(false),
            Some("New comment".to_string()),
            Some(false),
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Updated");
    assert!(!updated.enabled);
    assert_eq!(updated.comment.as_deref(), Some("New comment"));
    assert!(!updated.malware_detection_enabled);
}

#[tokio::test]
async fn test_update_group_omitted_fields_keep_stored_values() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create("Keep".to_string(), Some("note".to_string()), true, false)
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(id, None, Some(false), None, None)
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Keep");
    assert!(!updated.enabled);
    assert_eq!(updated.comment.as_deref(), Some("note"));
    assert!(!updated.malware_detection_enabled);
    let stored = repo.get_by_id(id).await.unwrap().unwrap();
    assert!(!stored.enabled);
    assert!(!stored.malware_detection_enabled);
}

#[tokio::test]
async fn test_update_missing_group_returns_group_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo
        .update(999, Some("X".to_string()), None, None, None)
        .await;

    assert!(matches!(result, Err(DomainError::GroupNotFound(999))));
}

#[tokio::test]
async fn test_update_to_existing_name_is_rejected() {
    let (repo, _pool) = repo().await;
    repo.create("Taken".to_string(), None, true, true)
        .await
        .unwrap();
    let id = repo
        .create("Other".to_string(), None, true, true)
        .await
        .unwrap()
        .id
        .unwrap();

    let result = repo
        .update(id, Some("Taken".to_string()), None, None, None)
        .await;

    assert!(matches!(result, Err(DomainError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_unique_name_constraint() {
    let (repo, _pool) = repo().await;
    repo.create("Unique Name".to_string(), None, true, true)
        .await
        .unwrap();

    let result = repo
        .create("Unique Name".to_string(), None, true, true)
        .await;

    assert!(matches!(result, Err(DomainError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_delete_group() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create("To Delete".to_string(), None, true, true)
        .await
        .unwrap()
        .id
        .unwrap();

    repo.delete(id).await.unwrap();

    assert!(repo.get_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_missing_group_returns_group_not_found() {
    let (repo, _pool) = repo().await;

    assert!(matches!(
        repo.delete(999).await,
        Err(DomainError::GroupNotFound(999))
    ));
}

#[tokio::test]
async fn test_delete_group_unassigns_its_clients() {
    let (repo, pool) = repo().await;
    let id = repo
        .create("Temp".to_string(), None, true, true)
        .await
        .unwrap()
        .id
        .unwrap();
    insert_client(&pool, "192.168.1.1", id).await;

    repo.delete(id).await.unwrap();

    let (clients, group_id): (i64, Option<i64>) =
        sqlx::query_as("SELECT COUNT(*), MAX(group_id) FROM clients")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((clients, group_id), (1, None));
}

#[tokio::test]
async fn test_count_clients_in_group() {
    let (repo, pool) = repo().await;
    insert_client(&pool, "192.168.1.1", 1).await;
    insert_client(&pool, "192.168.1.2", 1).await;

    assert_eq!(repo.count_clients_in_group(1).await.unwrap(), 2);
}

#[tokio::test]
async fn test_count_doh_ids_in_group() {
    let (repo, pool) = repo().await;
    sqlx::query("INSERT INTO doh_ids (name, client_id, group_id) VALUES (?, ?, ?), (?, ?, ?)")
        .bind("Alice Phone")
        .bind("alice-phone")
        .bind(1_i64)
        .bind("Alice Laptop")
        .bind("alice-laptop")
        .bind(1_i64)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(repo.count_doh_ids_in_group(1).await.unwrap(), 2);
}

#[tokio::test]
async fn test_get_clients_in_group() {
    let (repo, pool) = repo().await;
    let other = repo
        .create("Other".to_string(), None, true, true)
        .await
        .unwrap();
    insert_client(&pool, "192.168.1.1", 1).await;
    insert_client(&pool, "192.168.1.2", other.id.unwrap()).await;

    let clients = repo.get_clients_in_group(1).await.unwrap();

    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].ip_address.to_string(), "192.168.1.1");
    assert_eq!(clients[0].group_id, Some(1));
}
