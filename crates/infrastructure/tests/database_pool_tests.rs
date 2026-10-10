use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{
    create_query_log_pool, create_read_pool, create_write_pool,
};
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
