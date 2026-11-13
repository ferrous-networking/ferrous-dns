use ferrous_dns_application::ports::{ApiKeyMaterial, ApiTokenRepository};
use ferrous_dns_infrastructure::repositories::SqliteApiTokenRepository;

#[path = "support/db.rs"]
mod db;

fn make_repo(pool: sqlx::SqlitePool) -> SqliteApiTokenRepository {
    SqliteApiTokenRepository::new(pool)
}

#[tokio::test]
async fn create_returns_token_with_all_fields() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let token = repo
        .create("test-token", "abc12345", "sha256hash")
        .await
        .unwrap();

    assert!(token.id.is_some());
    assert_eq!(token.name.as_ref(), "test-token");
    assert_eq!(token.key_prefix.as_ref(), "abc12345");
    assert_eq!(token.key_hash.as_ref(), "sha256hash");
    assert!(token.created_at.is_some());
    assert!(token.last_used_at.is_none());
}

#[tokio::test]
async fn create_duplicate_name_returns_error() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    repo.create("dup", "pre", "hash1").await.unwrap();
    let err = repo.create("dup", "pre", "hash2").await.unwrap_err();

    assert!(
        matches!(err, ferrous_dns_domain::DomainError::DuplicateApiTokenName(ref n) if n == "dup")
    );
}

#[tokio::test]
async fn get_all_empty() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let tokens = repo.get_all().await.unwrap();
    assert!(tokens.is_empty());
}

#[tokio::test]
async fn get_all_returns_multiple() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    repo.create("first", "pre1", "hash1").await.unwrap();
    repo.create("second", "pre2", "hash2").await.unwrap();

    let tokens = repo.get_all().await.unwrap();
    assert_eq!(tokens.len(), 2);
}

#[tokio::test]
async fn get_by_id_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let created = repo.create("find-me", "pre", "hash").await.unwrap();
    let id = created.id.unwrap();

    let found = repo.get_by_id(id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().name.as_ref(), "find-me");
}

#[tokio::test]
async fn get_by_id_not_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    assert!(repo.get_by_id(999).await.unwrap().is_none());
}

#[tokio::test]
async fn get_by_name_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    repo.create("named", "pre", "hash").await.unwrap();

    let found = repo.get_by_name("named").await.unwrap();
    assert!(found.is_some());
}

#[tokio::test]
async fn get_by_name_not_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    assert!(repo.get_by_name("nope").await.unwrap().is_none());
}

#[tokio::test]
async fn update_name_only() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let created = repo.create("old-name", "pre", "hash").await.unwrap();
    let id = created.id.unwrap();

    let updated = repo.update(id, "new-name", None).await.unwrap();
    assert_eq!(updated.name.as_ref(), "new-name");
    assert_eq!(updated.key_hash.as_ref(), "hash");
}

#[tokio::test]
async fn update_name_and_key() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let created = repo.create("token", "pre", "hash").await.unwrap();
    let id = created.id.unwrap();

    let updated = repo
        .update(
            id,
            "token",
            Some(ApiKeyMaterial {
                prefix: "newpre",
                hash: "newhash",
            }),
        )
        .await
        .unwrap();

    assert_eq!(updated.key_prefix.as_ref(), "newpre");
    assert_eq!(updated.key_hash.as_ref(), "newhash");
}

#[tokio::test]
async fn update_nonexistent_returns_not_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let err = repo.update(999, "name", None).await.unwrap_err();
    assert!(matches!(
        err,
        ferrous_dns_domain::DomainError::ApiTokenNotFound(999)
    ));
}

#[tokio::test]
async fn update_duplicate_name_returns_error() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    repo.create("taken", "pre1", "hash1").await.unwrap();
    let second = repo.create("other", "pre2", "hash2").await.unwrap();
    let id2 = second.id.unwrap();

    let err = repo.update(id2, "taken", None).await.unwrap_err();
    assert!(matches!(
        err,
        ferrous_dns_domain::DomainError::DuplicateApiTokenName(_)
    ));
}

#[tokio::test]
async fn delete_existing() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let created = repo.create("del", "pre", "hash").await.unwrap();
    let id = created.id.unwrap();

    repo.delete(id).await.unwrap();
    assert!(repo.get_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_returns_error() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let err = repo.delete(999).await.unwrap_err();
    assert!(matches!(
        err,
        ferrous_dns_domain::DomainError::ApiTokenNotFound(999)
    ));
}

#[tokio::test]
async fn update_last_used_sets_timestamp() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let created = repo.create("used", "pre", "hash").await.unwrap();
    let id = created.id.unwrap();
    assert!(created.last_used_at.is_none());

    repo.update_last_used(id).await.unwrap();

    let token = repo.get_by_id(id).await.unwrap().unwrap();
    assert!(token.last_used_at.is_some());
}

#[tokio::test]
async fn get_id_by_hash_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let created = repo.create("token", "pre", "unique_hash").await.unwrap();
    let expected_id = created.id.unwrap();

    let found_id = repo.get_id_by_hash("unique_hash").await.unwrap();
    assert_eq!(found_id, Some(expected_id));
}

#[tokio::test]
async fn get_id_by_hash_not_found() {
    let pool = db::migrated_pool().await;
    let repo = make_repo(pool);

    let result = repo.get_id_by_hash("nonexistent").await.unwrap();
    assert!(result.is_none());
}
