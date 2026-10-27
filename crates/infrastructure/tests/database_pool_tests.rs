use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{
    create_query_log_pool, create_read_pool, create_write_pool,
};
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{Connection, SqliteConnection, SqlitePool};
use std::path::Path;
use std::str::FromStr;

async fn autocheckpoint_of_every_connection(pool: &SqlitePool, connections: u32) -> Vec<i64> {
    let mut held = Vec::new();
    for _ in 0..connections {
        held.push(pool.acquire().await.expect("acquire"));
    }
    let mut values = Vec::new();
    for conn in &mut held {
        let (pages,): (i64,) = sqlx::query_as("PRAGMA wal_autocheckpoint")
            .fetch_one(&mut **conn)
            .await
            .expect("read pragma");
        values.push(pages);
    }
    values
}

#[tokio::test]
async fn test_wal_autocheckpoint_applies_to_every_connection_of_every_pool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let cfg = DatabaseConfig {
        wal_autocheckpoint: 321,
        write_pool_max_connections: 3,
        query_log_pool_max_connections: 3,
        read_pool_max_connections: 3,
        ..DatabaseConfig::default()
    };

    let write = create_write_pool(&url, &cfg).await.expect("write pool");
    let query_log = create_query_log_pool(&url, &cfg)
        .await
        .expect("query log pool");
    let read = create_read_pool(&url, &cfg).await.expect("read pool");

    for (name, pool) in [
        ("write", &write),
        ("query_log", &query_log),
        ("read", &read),
    ] {
        assert_eq!(
            autocheckpoint_of_every_connection(pool, 3).await,
            vec![321; 3],
            "{name} pool"
        );
    }
}

fn wal_len(db_path: &Path) -> u64 {
    let mut wal = db_path.as_os_str().to_owned();
    wal.push("-wal");
    std::fs::metadata(wal).map(|m| m.len()).unwrap_or(0)
}

#[tokio::test]
async fn test_write_pool_folds_the_wal_left_by_a_previous_run_back_into_the_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.db");
    let url = format!("sqlite:{}", db_path.display());
    let cfg = DatabaseConfig::default();

    create_write_pool(&url, &cfg)
        .await
        .expect("first start")
        .close()
        .await;

    // A connection that is never closed stands in for a killed process: its
    // frames stay in the WAL, and the next start has to recover them.
    let options = SqliteConnectOptions::from_str(&url)
        .unwrap()
        .journal_mode(SqliteJournalMode::Wal)
        .pragma("wal_autocheckpoint", "0");
    let mut previous_run = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("CREATE TABLE leftover (v BLOB)")
        .execute(&mut previous_run)
        .await
        .unwrap();
    sqlx::query("INSERT INTO leftover VALUES (zeroblob(1048576))")
        .execute(&mut previous_run)
        .await
        .unwrap();
    let left_behind = wal_len(&db_path);
    assert!(
        left_behind > 1_048_576,
        "setup left {left_behind} WAL bytes"
    );

    let pool = create_write_pool(&url, &cfg).await.expect("second start");

    let after_start = wal_len(&db_path);
    assert!(
        after_start < left_behind,
        "startup kept the previous run's WAL: {after_start} bytes, was {left_behind}"
    );

    previous_run.close().await.unwrap();
    pool.close().await;
}

#[tokio::test]
async fn test_write_pool_estimates_missing_query_log_stats_instead_of_counting_the_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let cfg = DatabaseConfig::default();

    let pool = create_write_pool(&url, &cfg).await.expect("first start");
    // Ids 1..=1000 over three sources with the middle half deleted: counting every
    // index entry finds 500 rows, the id range says 1000.
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1000)
         INSERT INTO query_log (id, domain, record_type, client_ip, query_source, created_at)
         SELECT i, 'example.com', 'A', '10.0.0.1',
                CASE i % 3 WHEN 0 THEN 'client' WHEN 1 THEN 'internal' ELSE 'dnssec_validation' END,
                datetime(1700000000 + i, 'unixepoch')
         FROM n",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM query_log WHERE id BETWEEN 251 AND 750")
        .execute(&pool)
        .await
        .unwrap();
    // What an upgrade leaves behind: an index built over existing rows, never analyzed.
    sqlx::query("DELETE FROM sqlite_stat1 WHERE tbl = 'query_log'")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let pool = create_write_pool(&url, &cfg).await.expect("second start");

    let (stat,): (String,) =
        sqlx::query_as("SELECT stat FROM sqlite_stat1 WHERE idx = 'idx_query_log_window'")
            .fetch_one(&pool)
            .await
            .expect("idx_query_log_window has statistics after startup");
    assert_eq!(
        stat, "1000 334 1 1",
        "startup counted every row of query_log instead of estimating it"
    );

    let read = create_read_pool(&url, &cfg).await.expect("read pool");
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN SELECT rowid FROM query_log WHERE created_at < ? LIMIT 1000",
    )
    .bind("2023-11-15 00:00:00")
    .fetch_all(&read)
    .await
    .unwrap();
    assert!(
        plan.iter()
            .any(|(_, _, _, detail)| detail.contains("ANY(query_source)")),
        "retention cannot skip-scan the window index: {plan:?}"
    );

    read.close().await;
    pool.close().await;
}

async fn pragma(pool: &SqlitePool, name: &str) -> i64 {
    sqlx::query_scalar(&format!("PRAGMA {name}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_a_new_database_gives_freed_pages_back_incrementally() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());

    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("first start");

    assert_eq!(
        pragma(&pool, "auto_vacuum").await,
        2,
        "a new database must be created with auto_vacuum = INCREMENTAL"
    );
    pool.close().await;
}

#[tokio::test]
async fn test_query_log_retention_gives_the_deleted_pages_back_to_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let cfg = DatabaseConfig::default();
    let pool = create_write_pool(&url, &cfg).await.expect("first start");

    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20000)
         INSERT INTO query_log (domain, record_type, client_ip, query_source, created_at)
         SELECT printf('%0200d.example', i), 'A', '10.0.0.1', 'client',
                datetime('now', '-30 days')
         FROM n",
    )
    .execute(&pool)
    .await
    .unwrap();
    let pages_with_rows = pragma(&pool, "page_count").await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &cfg,
        Default::default(),
    );
    let deleted = repo.delete_older_than(7).await.unwrap();
    assert_eq!(deleted, 20_000);

    let free = pragma(&pool, "freelist_count").await;
    let pages = pragma(&pool, "page_count").await;
    assert_eq!(free, 0, "retention left {free} free pages in the file");
    assert!(
        pages * 4 < pages_with_rows,
        "the file kept {pages} of its {pages_with_rows} pages after retention emptied the log"
    );
    pool.close().await;
}

/// Pi-hole's flush deletes the whole log through the same call and answers an HTTP
/// request: giving a large file's pages back, paced, must not hold that answer.
#[tokio::test]
async fn test_deleting_old_rows_leaves_giving_the_pages_back_to_the_retention_job() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let cfg = DatabaseConfig::default();
    let pool = create_write_pool(&url, &cfg).await.expect("first start");
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000)
         INSERT INTO query_log (domain, record_type, client_ip, query_source, created_at)
         SELECT printf('%0200d.example', i), 'A', '10.0.0.1', 'client', datetime('now')
         FROM n",
    )
    .execute(&pool)
    .await
    .unwrap();
    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &cfg,
        Default::default(),
    );

    repo.delete_older_than(0).await.unwrap();

    assert!(
        pragma(&pool, "freelist_count").await > 0,
        "the delete gave the pages back itself, holding up a flush"
    );
    pool.close().await;
}
