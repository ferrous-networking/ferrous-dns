//! `--backup-database`: a copy of the live database, taken without stopping the server.

use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{backup_database, create_write_pool};
use sqlx::{Connection, SqliteConnection, SqlitePool};
use std::path::{Path, PathBuf};

async fn insert_query(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip) VALUES ('a', 'A', '10.0.0.1')",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn logged_queries(db: &Path) -> i64 {
    let mut conn = SqliteConnection::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let rows = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    rows
}

fn partial(target: &Path) -> PathBuf {
    target.with_extension("db.partial")
}

/// A database the way a running server holds it: migrated, open, with rows.
async fn live_database(dir: &Path) -> (String, SqlitePool) {
    let url = format!("sqlite:{}", dir.join("live.db").display());
    let server = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .unwrap();
    for _ in 0..100 {
        insert_query(&server).await;
    }
    (url, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_backup_copies_a_database_while_it_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = live_database(dir.path()).await;
    let writer = {
        let server = server.clone();
        tokio::spawn(async move {
            for _ in 0..2_000 {
                insert_query(&server).await;
            }
        })
    };
    let target = dir.path().join("backup.db");

    let report = backup_database(&url, &target).await.expect("backup");
    writer.await.unwrap();

    assert_eq!(report.bytes, std::fs::metadata(&target).unwrap().len());
    let copied = logged_queries(&target).await;
    assert!(
        (100..=2_100).contains(&copied),
        "the copy holds {copied} rows, not a state the database was in"
    );
    assert_eq!(
        logged_queries(&dir.path().join("live.db")).await,
        2_100,
        "the server's writes went on during the copy"
    );
    assert!(
        !partial(&target).exists(),
        "the partial file was left behind"
    );
    server.close().await;
}

#[tokio::test]
async fn test_backup_refuses_an_existing_target() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = live_database(dir.path()).await;
    let target = dir.path().join("backup.db");
    std::fs::write(&target, b"yesterday's backup").unwrap();

    let err = backup_database(&url, &target)
        .await
        .expect_err("an existing file must not be overwritten");

    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(std::fs::read(&target).unwrap(), b"yesterday's backup");
    server.close().await;
}

/// The copy holds password hashes, sessions and every client's queries.
#[cfg(unix)]
#[tokio::test]
async fn test_backup_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = live_database(dir.path()).await;
    let target = dir.path().join("backup.db");

    backup_database(&url, &target).await.expect("backup");

    let mode = std::fs::metadata(&target).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode {:o}", mode & 0o777);
    server.close().await;
}

#[tokio::test]
async fn test_failed_backup_leaves_no_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("missing.db").display());
    let target = dir.path().join("backup.db");

    backup_database(&url, &target)
        .await
        .expect_err("there is no database to copy");

    assert!(!target.exists());
    assert!(
        !partial(&target).exists(),
        "the partial file was left behind"
    );
    assert!(
        !dir.path().join("missing.db").exists(),
        "the backup created the database it was asked to copy"
    );
}

/// A symlink is a name too, even when what it points at is gone.
#[cfg(unix)]
#[tokio::test]
async fn test_backup_refuses_a_dangling_symlink_target() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = live_database(dir.path()).await;
    let target = dir.path().join("backup.db");
    std::os::unix::fs::symlink(dir.path().join("gone.db"), &target).unwrap();

    let err = backup_database(&url, &target)
        .await
        .expect_err("the symlink must not be replaced");

    assert!(err.to_string().contains("already exists"), "{err}");
    assert!(std::fs::symlink_metadata(&target)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(
        !partial(&target).exists(),
        "the partial file was left behind"
    );
    server.close().await;
}

#[tokio::test]
async fn test_backup_replaces_a_partial_file_left_by_an_interrupted_run() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = live_database(dir.path()).await;
    let target = dir.path().join("backup.db");
    std::fs::write(partial(&target), b"half-written copy").unwrap();

    backup_database(&url, &target).await.expect("backup");

    assert!(!partial(&target).exists());
    assert_eq!(logged_queries(&target).await, 100);
    server.close().await;
}
