//! `ferrous-dns --backup-database` runs beside the live server, the way a cron
//! job or `docker exec` calls it.
#![cfg(unix)]

mod server_process;

use server_process::{server_log, TestConfig};
use sqlx::{Connection, SqliteConnection};
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

#[tokio::test]
async fn test_backup_database_runs_beside_the_live_server() {
    let config = TestConfig::new();
    let _server = config.start();
    let target = config.dir.path().join("backup.db");

    let output = config
        .command()
        .arg("--backup-database")
        .arg(&target)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "backup failed: {}\nserver:\n{}",
        String::from_utf8_lossy(&output.stdout),
        server_log(config.dir.path())
    );
    let mode = std::fs::metadata(&target).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let mut copy = SqliteConnection::connect(&format!("sqlite:{}?mode=ro", target.display()))
        .await
        .unwrap();
    let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&mut copy)
        .await
        .unwrap();
    assert!(migrations > 0, "the copy is not the server's database");
    copy.close().await.unwrap();
}

#[test]
fn test_backup_and_compact_flags_conflict() {
    let config = TestConfig::new();
    let output = config
        .command()
        .arg("--backup-database")
        .arg(config.dir.path().join("backup.db"))
        .arg("--compact-database")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "clap rejects the pair");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!config.dir.path().join("backup.db").exists());
}
