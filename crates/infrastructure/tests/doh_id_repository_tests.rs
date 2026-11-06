#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::DohIdRepository;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::SqliteDohIdRepository;
use sqlx::SqlitePool;

const GUEST: i64 = 2;

async fn repo() -> (SqliteDohIdRepository, SqlitePool) {
    let pool = db::migrated_pool().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (?, 'Guest')")
        .bind(GUEST)
        .execute(&pool)
        .await
        .unwrap();
    (SqliteDohIdRepository::new(pool.clone()), pool)
}

#[tokio::test]
async fn test_create_and_lookup_doh_id() {
    let (repo, _pool) = repo().await;

    let created = repo
        .create(
            "Alice iPhone".to_string(),
            "alice-iphone".to_string(),
            1,
            Some("Personal phone".to_string()),
        )
        .await
        .unwrap();

    let id = created.id.unwrap();
    assert_eq!(created.name.as_ref(), "Alice iPhone");
    assert_eq!(created.client_id.as_ref(), "alice-iphone");
    assert_eq!(created.group_id, 1);
    assert_eq!(created.comment.as_deref(), Some("Personal phone"));
    assert!(created.created_at.is_some());

    let by_id = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(by_id.client_id.as_ref(), "alice-iphone");

    let by_client_id = repo
        .get_by_client_id("alice-iphone")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_client_id.id, Some(id));
    assert!(repo.get_by_client_id("missing").await.unwrap().is_none());
}

#[tokio::test]
async fn test_create_doh_id_rejects_duplicate_name_and_client_id() {
    let (repo, _pool) = repo().await;

    repo.create("Phone".to_string(), "phone-1".to_string(), 1, None)
        .await
        .unwrap();

    let dup_name = repo
        .create("Phone".to_string(), "phone-2".to_string(), GUEST, None)
        .await
        .unwrap_err();
    assert!(matches!(&dup_name, DomainError::DohIdConflict(msg) if msg.contains("name")));

    let dup_cid = repo
        .create("Phone 2".to_string(), "phone-1".to_string(), GUEST, None)
        .await
        .unwrap_err();
    assert!(matches!(&dup_cid, DomainError::DohIdConflict(msg) if msg.contains("client ID")));
}

#[tokio::test]
async fn test_create_doh_id_invalid_group_fk() {
    let (repo, _pool) = repo().await;

    let err = repo
        .create("Phone".to_string(), "phone-1".to_string(), 999, None)
        .await
        .unwrap_err();
    assert!(matches!(err, DomainError::GroupNotFound(999)));
}

#[tokio::test]
async fn test_update_doh_id_replaces_fields_and_clears_comment() {
    let (repo, _pool) = repo().await;

    let created = repo
        .create(
            "Old Name".to_string(),
            "old-id".to_string(),
            1,
            Some("Old comment".to_string()),
        )
        .await
        .unwrap();
    let id = created.id.unwrap();

    // Update keeping client_id (None) and clearing comment (None).
    let updated = repo
        .update(id, "New Name".to_string(), None, GUEST, None)
        .await
        .unwrap();
    assert_eq!(updated.name.as_ref(), "New Name");
    assert_eq!(updated.client_id.as_ref(), "old-id");
    assert_eq!(updated.group_id, GUEST);
    assert!(updated.comment.is_none());

    // Rotate client_id.
    let rotated = repo
        .update(
            id,
            "New Name".to_string(),
            Some("new-id".to_string()),
            GUEST,
            Some("Rotated".to_string()),
        )
        .await
        .unwrap();
    assert_eq!(rotated.client_id.as_ref(), "new-id");
    assert_eq!(rotated.comment.as_deref(), Some("Rotated"));

    assert!(matches!(
        repo.update(999, "Ghost".to_string(), None, 1, None).await,
        Err(DomainError::DohIdNotFound(999))
    ));
}

#[tokio::test]
async fn test_delete_doh_id_and_group_cascade() {
    let (repo, pool) = repo().await;

    let entry1 = repo
        .create(
            "Guest Laptop".to_string(),
            "guest-laptop".to_string(),
            GUEST,
            None,
        )
        .await
        .unwrap();
    let entry2 = repo
        .create(
            "Home Laptop".to_string(),
            "home-laptop".to_string(),
            1,
            None,
        )
        .await
        .unwrap();

    assert_eq!(repo.get_all().await.unwrap().len(), 2);

    // Deleting the parent group cascades to its DoH IDs.
    sqlx::query("DELETE FROM groups WHERE id = ?")
        .bind(GUEST)
        .execute(&pool)
        .await
        .unwrap();

    assert!(repo.get_by_id(entry1.id.unwrap()).await.unwrap().is_none());
    assert!(repo.get_by_id(entry2.id.unwrap()).await.unwrap().is_some());

    repo.delete(entry2.id.unwrap()).await.unwrap();
    assert!(matches!(
        repo.delete(entry2.id.unwrap()).await,
        Err(DomainError::DohIdNotFound(_))
    ));
}
