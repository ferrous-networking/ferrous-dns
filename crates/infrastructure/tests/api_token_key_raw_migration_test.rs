//! `20261113000001_drop_api_token_key_raw`, run over a database migrated to
//! the schema before it. The table kept every token's key in plaintext beside
//! its hash; after the migration only the hash is left, and a token made
//! before the upgrade still authenticates.

use ferrous_dns_application::ports::ApiTokenRepository;
use ferrous_dns_infrastructure::repositories::SqliteApiTokenRepository;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

const VERSION: i64 = 20261113000001;
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

async fn pool_before_the_migration() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let earlier = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < VERSION)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    earlier.run(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn test_migration_drops_the_plaintext_key_and_keeps_the_token_working() {
    let pool = pool_before_the_migration().await;
    sqlx::query(
        "INSERT INTO api_tokens (name, key_prefix, key_hash, key_raw)
         VALUES ('homelab', 'f3a1c2d4', 'stored-hash', 'the-plaintext-key')",
    )
    .execute(&pool)
    .await
    .unwrap();

    MIGRATOR.run(&pool).await.unwrap();

    let columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('api_tokens')")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        !columns.iter().any(|c| c == "key_raw"),
        "the plaintext key column survived: {columns:?}"
    );

    let repo = SqliteApiTokenRepository::new(pool);
    assert!(repo.get_id_by_hash("stored-hash").await.unwrap().is_some());
}

/// Before the upgrade a key's first 8 characters were its listed prefix, which
/// is the whole of a short custom key. The migration shortens each prefix to
/// at most a quarter of its key, as new keys get.
#[tokio::test]
async fn test_migration_shows_at_most_a_quarter_of_each_key_as_its_prefix() {
    let pool = pool_before_the_migration().await;
    let generated = "c871aa2693522d13a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081";
    for (name, key) in [("short", "abcdefgh"), ("generated", generated)] {
        sqlx::query(
            "INSERT INTO api_tokens (name, key_prefix, key_hash, key_raw)
             VALUES (?, substr(?, 1, 8), ?, ?)",
        )
        .bind(name)
        .bind(key)
        .bind(format!("hash-{name}"))
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    }

    MIGRATOR.run(&pool).await.unwrap();

    let prefixes: Vec<(String, String)> =
        sqlx::query_as("SELECT name, key_prefix FROM api_tokens ORDER BY name")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        prefixes,
        [
            ("generated".to_string(), generated[..8].to_string()),
            ("short".to_string(), "ab".to_string()),
        ]
    );
}
