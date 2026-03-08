use ferrous_dns_application::ports::ApiTokenRepository;
use ferrous_dns_infrastructure::repositories::SqliteApiTokenRepository;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to create in-memory SQLite pool");

    sqlx::query(
        "CREATE TABLE api_tokens (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL UNIQUE,
            key_prefix   TEXT    NOT NULL,
            key_hash     TEXT    NOT NULL,
            key_raw      TEXT,
            created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
            last_used_at TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create api_tokens table");

    sqlx::query("CREATE INDEX idx_api_tokens_name ON api_tokens(name)")
        .execute(&pool)
        .await
        .expect("Failed to create name index");

    sqlx::query("CREATE INDEX idx_api_tokens_key_hash ON api_tokens(key_hash)")
        .execute(&pool)
        .await
        .expect("Failed to create key_hash index");

    pool
}

fn make_repo(pool: sqlx::SqlitePool) -> SqliteApiTokenRepository {
    SqliteApiTokenRepository::new(Arc::new(pool))
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_returns_token_with_all_fields() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let token = repo
        .create("test-token", "abc12345", "sha256hash", "rawvalue")
        .await
        .unwrap();

    assert!(token.id.is_some());
    assert_eq!(token.name.as_ref(), "test-token");
    assert_eq!(token.key_prefix.as_ref(), "abc12345");
    assert_eq!(token.key_hash.as_ref(), "sha256hash");
    assert_eq!(token.key_raw.as_deref(), Some("rawvalue"));
    assert!(token.created_at.is_some());
    assert!(token.last_used_at.is_none());
}

#[tokio::test]
async fn create_duplicate_name_returns_error() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    repo.create("dup", "pre", "hash1", "raw1").await.unwrap();
    let err = repo
        .create("dup", "pre", "hash2", "raw2")
        .await
        .unwrap_err();

    assert!(
        matches!(err, ferrous_dns_domain::DomainError::DuplicateApiTokenName(ref n) if n == "dup")
    );
}

// ---------------------------------------------------------------------------
// get_all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_all_empty() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let tokens = repo.get_all().await.unwrap();
    assert!(tokens.is_empty());
}

#[tokio::test]
async fn get_all_returns_multiple() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    repo.create("first", "pre1", "hash1", "raw1").await.unwrap();
    repo.create("second", "pre2", "hash2", "raw2")
        .await
        .unwrap();

    let tokens = repo.get_all().await.unwrap();
    assert_eq!(tokens.len(), 2);
}

// ---------------------------------------------------------------------------
// get_by_id / get_by_name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_id_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let created = repo.create("find-me", "pre", "hash", "raw").await.unwrap();
    let id = created.id.unwrap();

    let found = repo.get_by_id(id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().name.as_ref(), "find-me");
}

#[tokio::test]
async fn get_by_id_not_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    assert!(repo.get_by_id(999).await.unwrap().is_none());
}

#[tokio::test]
async fn get_by_name_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    repo.create("named", "pre", "hash", "raw").await.unwrap();

    let found = repo.get_by_name("named").await.unwrap();
    assert!(found.is_some());
}

#[tokio::test]
async fn get_by_name_not_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    assert!(repo.get_by_name("nope").await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_name_only() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let created = repo.create("old-name", "pre", "hash", "raw").await.unwrap();
    let id = created.id.unwrap();

    let updated = repo.update(id, "new-name", None, None, None).await.unwrap();
    assert_eq!(updated.name.as_ref(), "new-name");
    assert_eq!(updated.key_hash.as_ref(), "hash");
}

#[tokio::test]
async fn update_name_and_key() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let created = repo.create("token", "pre", "hash", "raw").await.unwrap();
    let id = created.id.unwrap();

    let updated = repo
        .update(id, "token", Some("newpre"), Some("newhash"), Some("newraw"))
        .await
        .unwrap();

    assert_eq!(updated.key_prefix.as_ref(), "newpre");
    assert_eq!(updated.key_hash.as_ref(), "newhash");
    assert_eq!(updated.key_raw.as_deref(), Some("newraw"));
}

#[tokio::test]
async fn update_nonexistent_returns_not_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let err = repo
        .update(999, "name", None, None, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ferrous_dns_domain::DomainError::ApiTokenNotFound(999)
    ));
}

#[tokio::test]
async fn update_duplicate_name_returns_error() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    repo.create("taken", "pre1", "hash1", "raw1").await.unwrap();
    let second = repo.create("other", "pre2", "hash2", "raw2").await.unwrap();
    let id2 = second.id.unwrap();

    let err = repo
        .update(id2, "taken", None, None, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ferrous_dns_domain::DomainError::DuplicateApiTokenName(_)
    ));
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_existing() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let created = repo.create("del", "pre", "hash", "raw").await.unwrap();
    let id = created.id.unwrap();

    repo.delete(id).await.unwrap();
    assert!(repo.get_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_returns_error() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let err = repo.delete(999).await.unwrap_err();
    assert!(matches!(
        err,
        ferrous_dns_domain::DomainError::ApiTokenNotFound(999)
    ));
}

// ---------------------------------------------------------------------------
// update_last_used
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_last_used_sets_timestamp() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let created = repo.create("used", "pre", "hash", "raw").await.unwrap();
    let id = created.id.unwrap();
    assert!(created.last_used_at.is_none());

    repo.update_last_used(id).await.unwrap();

    let token = repo.get_by_id(id).await.unwrap().unwrap();
    assert!(token.last_used_at.is_some());
}

// ---------------------------------------------------------------------------
// get_all_hashes / get_id_by_hash
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_all_hashes_returns_pairs() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    repo.create("a", "pre1", "hash_a", "raw1").await.unwrap();
    repo.create("b", "pre2", "hash_b", "raw2").await.unwrap();

    let hashes = repo.get_all_hashes().await.unwrap();
    assert_eq!(hashes.len(), 2);

    let hash_strings: Vec<&str> = hashes.iter().map(|(_, h)| h.as_str()).collect();
    assert!(hash_strings.contains(&"hash_a"));
    assert!(hash_strings.contains(&"hash_b"));
}

#[tokio::test]
async fn get_id_by_hash_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let created = repo
        .create("token", "pre", "unique_hash", "raw")
        .await
        .unwrap();
    let expected_id = created.id.unwrap();

    let found_id = repo.get_id_by_hash("unique_hash").await.unwrap();
    assert_eq!(found_id, Some(expected_id));
}

#[tokio::test]
async fn get_id_by_hash_not_found() {
    let pool = create_test_db().await;
    let repo = make_repo(pool);

    let result = repo.get_id_by_hash("nonexistent").await.unwrap();
    assert!(result.is_none());
}
