//! Session ids are stored as their SHA-256, so a copy of the database holds
//! no live session cookie. Sessions written before the upgrade are rewritten
//! once when the database opens, and their cookies keep working.

use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::create_write_pool;
use sha2::{Digest, Sha256};
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use std::borrow::Cow;
use std::fmt::Write;

const VERSION: i64 = 20261113000002;
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");
const LEGACY_COOKIE: &str = "4f9c0d1e2b3a4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5";

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// A database file at the schema before the migration, holding one session
/// stored the old way, under its plaintext id.
async fn legacy_database(dir: &std::path::Path) -> String {
    let url = format!("sqlite:{}?mode=rwc", dir.join("ferrous.db").display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
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
    sqlx::query(
        "INSERT INTO auth_sessions (id, username, role, ip_address, expires_at)
         VALUES (?, 'admin', 'admin', '127.0.0.1', '2999-01-01 00:00:00')",
    )
    .bind(LEGACY_COOKIE)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    url
}

async fn stored_ids(url: &str) -> Vec<String> {
    let pool = create_write_pool(url, &DatabaseConfig::default())
        .await
        .unwrap();
    let ids = sqlx::query_scalar("SELECT id FROM auth_sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
    ids
}

#[tokio::test]
async fn test_opening_the_database_hashes_sessions_stored_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let url = legacy_database(dir.path()).await;

    assert_eq!(stored_ids(&url).await, [sha256_hex(LEGACY_COOKIE)]);
}

#[tokio::test]
async fn test_a_second_open_does_not_hash_a_session_again() {
    let dir = tempfile::tempdir().unwrap();
    let url = legacy_database(dir.path()).await;

    stored_ids(&url).await;
    assert_eq!(stored_ids(&url).await, [sha256_hex(LEGACY_COOKIE)]);
}
