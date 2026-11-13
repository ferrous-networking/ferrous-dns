//! The upgrade that drops `api_tokens.key_raw` and hashes `auth_sessions.id`
//! must also leave neither the plaintext keys nor the old cookies in the
//! file: SQLite keeps a dropped column's and an updated key's bytes in free
//! pages, and both values still sign in.

use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::create_write_pool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use std::borrow::Cow;
use std::path::Path;

const FIRST_NEW_MIGRATION: i64 = 20261113000001;
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");
/// Enough rows to span several pages, so freed copies outlive a checkpoint.
const ROWS: usize = 200;

fn key(i: usize) -> String {
    format!("PLAINKEY{i:056}")
}

fn cookie(i: usize) -> String {
    format!("OLDCOOKIE{i:055}")
}

/// A database file at the schema before the upgrade, holding `tokens` tokens
/// with their plaintext keys and `sessions` sessions under their plaintext ids.
async fn legacy_database(dir: &Path, tokens: usize, sessions: usize) -> String {
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
                .filter(|m| m.version < FIRST_NEW_MIGRATION)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    earlier.run(&pool).await.unwrap();
    for i in 0..tokens {
        sqlx::query(
            "INSERT INTO api_tokens (name, key_prefix, key_hash, key_raw)
             VALUES (?, 'PLAINKEY', ?, ?)",
        )
        .bind(format!("token-{i}"))
        .bind(format!("hash-{i}"))
        .bind(key(i))
        .execute(&pool)
        .await
        .unwrap();
    }
    for i in 0..sessions {
        sqlx::query(
            "INSERT INTO auth_sessions (id, username, role, ip_address, expires_at)
             VALUES (?, 'admin', 'admin', '127.0.0.1', '2999-01-01 00:00:00')",
        )
        .bind(cookie(i))
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    url
}

fn file_bytes(dir: &Path) -> Vec<u8> {
    ["ferrous.db", "ferrous.db-wal"]
        .iter()
        .filter_map(|name| std::fs::read(dir.join(name)).ok())
        .flatten()
        .collect()
}

fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Upgrades a legacy file and counts the plaintext keys and old cookies found
/// in it, or its WAL, while the server holds it open and again once the WAL is
/// copied back, as the checkpoint job does.
async fn left_after_upgrade(tokens: usize, sessions: usize) -> (usize, usize) {
    let dir = tempfile::tempdir().unwrap();
    let url = legacy_database(dir.path(), tokens, sessions).await;
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .unwrap();
    let mut bytes = file_bytes(dir.path());
    pool.close().await;
    let single = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let (busy, _, _): (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(busy, 0, "checkpoint did not complete");
    single.close().await;

    bytes.extend(file_bytes(dir.path()));
    (
        (0..tokens).filter(|&i| holds(&bytes, &key(i))).count(),
        (0..sessions).filter(|&i| holds(&bytes, &cookie(i))).count(),
    )
}

#[tokio::test]
async fn test_upgrade_leaves_no_plaintext_key_or_legacy_cookie_in_the_file() {
    let (keys, cookies) = left_after_upgrade(ROWS, ROWS).await;
    assert!(
        keys == 0 && cookies == 0,
        "after the upgrade and a checkpoint the file still holds {keys}/{ROWS} plaintext \
         API keys and {cookies}/{ROWS} legacy session cookies"
    );
}

/// Either kind of replaced credential alone is reason enough to rewrite the file.
#[tokio::test]
async fn test_upgrade_wipes_tokens_without_sessions_and_sessions_without_tokens() {
    assert_eq!(left_after_upgrade(ROWS, 0).await, (0, 0), "tokens only");
    assert_eq!(left_after_upgrade(0, ROWS).await, (0, 0), "sessions only");
}

#[tokio::test]
async fn test_opening_an_upgraded_database_again_rewrites_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let url = legacy_database(dir.path(), ROWS, ROWS).await;
    create_write_pool(&url, &DatabaseConfig::default())
        .await
        .unwrap()
        .close()
        .await;

    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .unwrap();
    let (sessions, tokens): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_sessions), (SELECT count(*) FROM api_tokens)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((sessions, tokens), (ROWS as i64, ROWS as i64));
}
