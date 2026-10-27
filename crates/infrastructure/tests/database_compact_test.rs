use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{compact_database, create_write_pool};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{Connection, SqliteConnection};
use std::path::Path;
use std::str::FromStr;

async fn pragma(conn: &mut SqliteConnection, name: &str) -> i64 {
    sqlx::query_scalar(&format!("PRAGMA {name}"))
        .fetch_one(conn)
        .await
        .unwrap()
}

/// A database as releases before incremental auto-vacuum left it: WAL mode, no
/// auto-vacuum, and most of its pages on the freelist after a delete.
async fn old_database_with_free_pages(url: &str) {
    let options = SqliteConnectOptions::from_str(url)
        .unwrap()
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::raw_sql(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB);
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000)
         INSERT INTO t SELECT i, zeroblob(4000) FROM n;
         DELETE FROM t WHERE id > 500;",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    assert_eq!(pragma(&mut conn, "auto_vacuum").await, 0);
    assert!(pragma(&mut conn, "freelist_count").await > 1000);
    conn.close().await.unwrap();
}

fn compact_copy(db: &Path) -> std::path::PathBuf {
    db.with_extension("db.compact")
}

#[tokio::test]
async fn test_compacting_an_old_database_drops_its_free_pages_and_keeps_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("old.db");
    let url = format!("sqlite:{}", db.display());
    old_database_with_free_pages(&url).await;

    let report = compact_database(&url).await.expect("compaction");

    assert!(
        report.bytes_after * 2 < report.bytes_before,
        "the file did not shrink: {report:?}"
    );
    assert!(!compact_copy(&db).exists(), "the copy was left behind");
    let mut conn = SqliteConnection::connect(&url).await.unwrap();
    assert_eq!(
        pragma(&mut conn, "auto_vacuum").await,
        2,
        "the compacted database must give pages back from now on"
    );
    assert_eq!(pragma(&mut conn, "freelist_count").await, 0);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t WHERE length(v) = 4000")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(rows, 500);
    conn.close().await.unwrap();
}

#[tokio::test]
async fn test_compacting_refuses_a_database_a_running_server_holds_open() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.db");
    let url = format!("sqlite:{}", db.display());
    let server = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .unwrap();
    let before = std::fs::read(&db).unwrap();

    let err = compact_database(&url)
        .await
        .expect_err("compaction must not run under a live server");

    assert!(
        err.to_string().contains("stop the server"),
        "unexpected error: {err}"
    );
    assert_eq!(std::fs::read(&db).unwrap(), before, "the database changed");
    assert!(!compact_copy(&db).exists(), "a copy was left behind");
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip) VALUES ('a', 'A', '10.0.0.1')",
    )
    .execute(&server)
    .await
    .expect("the server keeps writing");
    server.close().await;
}

#[tokio::test]
async fn test_compacting_replaces_a_copy_left_by_an_interrupted_run() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("old.db");
    let url = format!("sqlite:{}", db.display());
    old_database_with_free_pages(&url).await;
    std::fs::write(compact_copy(&db), b"half-written copy").unwrap();

    compact_database(&url).await.expect("compaction");

    assert!(!compact_copy(&db).exists());
    let mut conn = SqliteConnection::connect(&url).await.unwrap();
    assert_eq!(pragma(&mut conn, "freelist_count").await, 0);
    conn.close().await.unwrap();
}
