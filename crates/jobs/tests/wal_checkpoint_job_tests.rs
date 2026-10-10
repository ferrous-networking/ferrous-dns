use ferrous_dns_jobs::{WalCheckpointJob, WalCheckpointOutcome};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Connection, SqliteConnection, SqlitePool};
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "ferrous-jobs-wal-{tag}-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        )))
    }

    fn wal_len(&self) -> u64 {
        let mut wal = self.0.clone().into_os_string();
        wal.push("-wal");
        std::fs::metadata(wal).map_or(0, |m| m.len())
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(path);
        }
    }
}

#[tokio::test]
async fn test_wal_checkpoint_reports_reader_pinned_wal_as_partial() {
    let db = TempDb::new("partial");
    let options = SqliteConnectOptions::new()
        .filename(&db.0)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .pragma("wal_autocheckpoint", "0");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();

    sqlx::query("CREATE TABLE t (v INTEGER)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES (1)")
        .execute(&pool)
        .await
        .unwrap();

    // The reader's snapshot ends at the current WAL frame, so later frames cannot be copied back.
    let mut reader = SqliteConnection::connect_with(&options).await.unwrap();
    let mut snapshot = reader.begin().await.unwrap();
    sqlx::query("SELECT count(*) FROM t")
        .fetch_one(&mut *snapshot)
        .await
        .unwrap();

    sqlx::query("INSERT INTO t VALUES (2)")
        .execute(&pool)
        .await
        .unwrap();

    let job = WalCheckpointJob::new(pool.clone(), 1);

    let pinned = job.checkpoint_once().await.unwrap();
    assert!(
        matches!(
            pinned,
            WalCheckpointOutcome::Partial { log_frames, checkpointed_frames }
                if checkpointed_frames < log_frames
        ),
        "pinned WAL reported as {pinned:?}"
    );

    snapshot.rollback().await.unwrap();

    let released = job.checkpoint_once().await.unwrap();
    assert!(
        matches!(released, WalCheckpointOutcome::Complete { frames } if frames > 0),
        "released WAL reported as {released:?}"
    );

    reader.close().await.unwrap();
    pool.close().await;
}

/// A pool whose connections wait 30 s on a busy lock, holding a WAL of about 17 000
/// frames (some 70 MB), above the 64 MiB the job lets the WAL keep.
async fn pool_with_large_wal(db: &TempDb) -> (SqlitePool, SqliteConnectOptions) {
    let options = SqliteConnectOptions::new()
        .filename(&db.0)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(30))
        .pragma("wal_autocheckpoint", "0");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    sqlx::query("CREATE TABLE t (v BLOB)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 17000)
         INSERT INTO t SELECT zeroblob(4000) FROM n",
    )
    .execute(&pool)
    .await
    .unwrap();
    (pool, options)
}

#[tokio::test]
async fn test_wal_checkpoint_truncates_a_wal_over_the_size_limit() {
    let db = TempDb::new("truncate");
    let (pool, _) = pool_with_large_wal(&db).await;
    let before = db.wal_len();
    assert!(before > 64 * 1024 * 1024, "setup left {before} WAL bytes");

    let outcome = WalCheckpointJob::new(pool.clone(), 1)
        .checkpoint_once()
        .await
        .unwrap();

    assert_eq!(
        db.wal_len(),
        0,
        "a {before}-byte WAL was left in place, reported as {outcome:?}"
    );

    pool.close().await;
}

#[tokio::test]
async fn test_wal_checkpoint_gives_up_on_truncating_quickly_when_a_reader_pins_the_wal() {
    let db = TempDb::new("truncate-pinned");
    let (pool, options) = pool_with_large_wal(&db).await;

    let mut reader = SqliteConnection::connect_with(&options).await.unwrap();
    let mut snapshot = reader.begin().await.unwrap();
    sqlx::query("SELECT count(*) FROM t")
        .fetch_one(&mut *snapshot)
        .await
        .unwrap();
    let before = db.wal_len();

    // Truncating waits for readers while holding off new writers, so the wait must
    // stay far below the pool's 30 s busy timeout.
    let started = Instant::now();
    let outcome = WalCheckpointJob::new(pool.clone(), 1)
        .checkpoint_once()
        .await
        .unwrap();
    let waited = started.elapsed();

    assert!(
        waited < Duration::from_secs(5),
        "the checkpoint held writers off for {waited:?}"
    );
    assert_eq!(db.wal_len(), before, "reported as {outcome:?}");

    snapshot.rollback().await.unwrap();
    reader.close().await.unwrap();
    pool.close().await;
}
